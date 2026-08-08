use std::cell::UnsafeCell;
use std::mem::MaybeUninit;
use std::ops::Deref;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Pad a value to fill a full cache line (64 bytes on x86_64/aarch64).
///
/// `#[repr(align(64))]` rounds the wrapper's size up to a multiple of 64 and
/// aligns each instance to a cache-line boundary. In `SpscRing`, the producer
/// writes `tail` while the consumer writes `head`; this guarantees the two
/// atomics never share a cache line, avoiding the false sharing that would
/// otherwise dominate SPSC throughput under contention.
#[repr(align(64))]
struct CachePadded<T> {
    value: T,
}

impl<T> CachePadded<T> {
    #[inline]
    fn new(value: T) -> Self {
        Self { value }
    }
}

impl<T> Deref for CachePadded<T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        &self.value
    }
}

/// Lock-free single-producer/single-consumer ring buffer.
///
/// The queue is bounded and non-blocking:
/// - `push` returns `Err(value)` when full
/// - `pop` returns `None` when empty
///
/// `head` (consumer) and `tail` (producer) live on separate cache lines to
/// avoid false sharing under concurrent producer/consumer access.
pub struct SpscRing<T> {
    buffer: Box<[UnsafeCell<MaybeUninit<T>>]>,
    capacity: usize,
    head: CachePadded<AtomicUsize>,
    tail: CachePadded<AtomicUsize>,
}

// Safety: single producer + single consumer semantics are enforced by API usage.
unsafe impl<T: Send> Send for SpscRing<T> {}
unsafe impl<T: Send> Sync for SpscRing<T> {}

impl<T> SpscRing<T> {
    pub fn with_capacity(capacity: usize) -> Self {
        assert!(capacity > 0, "SpscRing capacity must be > 0");
        let mut v = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            v.push(UnsafeCell::new(MaybeUninit::uninit()));
        }
        Self {
            buffer: v.into_boxed_slice(),
            capacity,
            head: CachePadded::new(AtomicUsize::new(0)),
            tail: CachePadded::new(AtomicUsize::new(0)),
        }
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    #[inline]
    pub fn len(&self) -> usize {
        // Relaxed is sufficient: these are approximate diagnostic snapshots
        // and do not synchronize the payload slots.
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Relaxed);
        tail.saturating_sub(head)
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.head.load(Ordering::Relaxed) == self.tail.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn push(&self, value: T) -> Result<(), T> {
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire);
        if tail.wrapping_sub(head) >= self.capacity {
            return Err(value);
        }

        let idx = tail % self.capacity;
        // Safety: producer is the only writer for this slot, and slot is empty because queue isn't full.
        unsafe {
            (*self.buffer[idx].get()).write(value);
        }
        self.tail.store(tail.wrapping_add(1), Ordering::Release);
        Ok(())
    }

    #[inline]
    pub fn pop(&self) -> Option<T> {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        if head == tail {
            return None;
        }

        let idx = head % self.capacity;
        // Safety: consumer is the only reader for this slot, and slot is initialized because queue isn't empty.
        let value = unsafe { (*self.buffer[idx].get()).assume_init_read() };
        self.head.store(head.wrapping_add(1), Ordering::Release);
        Some(value)
    }
}

impl<T> Drop for SpscRing<T> {
    fn drop(&mut self) {
        let mut head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Relaxed);
        while head != tail {
            let idx = head % self.capacity;
            // Safety: remaining queued elements are initialized and must be dropped.
            unsafe {
                (*self.buffer[idx].get()).assume_init_drop();
            }
            head = head.wrapping_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SpscRing;

    #[test]
    fn push_pop_roundtrip() {
        let q = SpscRing::with_capacity(4);
        assert!(q.is_empty());
        q.push(1).unwrap();
        q.push(2).unwrap();
        assert_eq!(q.len(), 2);
        assert_eq!(q.pop(), Some(1));
        assert_eq!(q.pop(), Some(2));
        assert_eq!(q.pop(), None);
    }

    #[test]
    fn full_returns_err() {
        let q = SpscRing::with_capacity(2);
        q.push(1).unwrap();
        q.push(2).unwrap();
        assert_eq!(q.push(3), Err(3));
    }

    #[test]
    fn head_and_tail_are_cache_line_separated() {
        use std::sync::atomic::AtomicUsize;
        use super::CachePadded;
        // Each padded atomic must occupy exactly one 64-byte cache line so the
        // producer's `tail` and consumer's `head` cannot false-share.
        assert_eq!(std::mem::size_of::<CachePadded<AtomicUsize>>(), 64);
        assert_eq!(std::mem::align_of::<CachePadded<AtomicUsize>>(), 64);
        // The whole ring embeds both padded atomics.
        let q = SpscRing::<u8>::with_capacity(4);
        let head_addr = &q.head as *const _ as usize;
        let tail_addr = &q.tail as *const _ as usize;
        // They must be on different 64-byte cache lines.
        assert_ne!(head_addr / 64, tail_addr / 64);
    }
}
