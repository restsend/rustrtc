use std::cell::UnsafeCell;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Lock-free single-producer/single-consumer ring buffer.
///
/// The queue is bounded and non-blocking:
/// - `push` returns `Err(value)` when full
/// - `pop` returns `None` when empty
pub struct SpscRing<T> {
    buffer: Box<[UnsafeCell<MaybeUninit<T>>]>,
    capacity: usize,
    head: AtomicUsize,
    tail: AtomicUsize,
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
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
        }
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    #[inline]
    pub fn len(&self) -> usize {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        tail.saturating_sub(head)
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.head.load(Ordering::Acquire) == self.tail.load(Ordering::Acquire)
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
}
