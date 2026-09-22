use std::collections::VecDeque;

pub struct FaxPage {
    pub width: usize,
    pub height: usize,
    pub rows: Vec<Vec<u8>>,
}

pub const WHITE_CODES: &[(u8, u16, u16)] = &[
    (8, 53, 0),
    (6, 7, 1),
    (4, 7, 2),
    (4, 8, 3),
    (4, 11, 4),
    (4, 12, 5),
    (4, 14, 6),
    (4, 15, 7),
    (5, 19, 8),
    (5, 20, 9),
    (5, 7, 10),
    (5, 8, 11),
    (6, 8, 12),
    (6, 3, 13),
    (6, 52, 14),
    (6, 53, 15),
    (6, 42, 16),
    (6, 43, 17),
    (7, 39, 18),
    (7, 12, 19),
    (7, 8, 20),
    (7, 23, 21),
    (7, 3, 22),
    (7, 4, 23),
    (7, 40, 24),
    (7, 43, 25),
    (7, 19, 26),
    (7, 36, 27),
    (7, 24, 28),
    (8, 2, 29),
    (8, 3, 30),
    (8, 26, 31),
    (8, 27, 32),
    (8, 18, 33),
    (8, 19, 34),
    (8, 20, 35),
    (8, 21, 36),
    (8, 22, 37),
    (8, 23, 38),
    (8, 40, 39),
    (8, 41, 40),
    (8, 42, 41),
    (8, 43, 42),
    (8, 44, 43),
    (8, 45, 44),
    (8, 4, 45),
    (8, 5, 46),
    (8, 10, 47),
    (8, 11, 48),
    (8, 82, 49),
    (8, 83, 50),
    (8, 84, 51),
    (8, 85, 52),
    (8, 36, 53),
    (8, 37, 54),
    (8, 88, 55),
    (8, 89, 56),
    (8, 90, 57),
    (8, 91, 58),
    (8, 74, 59),
    (8, 75, 60),
    (8, 50, 61),
    (8, 51, 62),
    (8, 52, 63),
    (5, 27, 64),
    (5, 18, 128),
    (6, 23, 192),
    (7, 55, 256),
    (8, 54, 320),
    (8, 55, 384),
    (8, 100, 448),
    (8, 101, 512),
    (8, 104, 576),
    (8, 103, 640),
    (9, 204, 704),
    (9, 205, 768),
    (9, 210, 832),
    (9, 211, 896),
    (9, 212, 960),
    (9, 213, 1024),
    (9, 214, 1088),
    (9, 215, 1152),
    (9, 216, 1216),
    (9, 217, 1280),
    (9, 218, 1344),
    (9, 219, 1408),
    (9, 152, 1472),
    (9, 153, 1536),
    (9, 154, 1600),
    (6, 24, 1664),
    (9, 155, 1728),
    (11, 8, 1792),
    (11, 12, 1856),
    (11, 13, 1920),
    (12, 18, 1984),
    (12, 19, 2048),
    (12, 20, 2112),
    (12, 21, 2176),
    (12, 22, 2240),
    (12, 23, 2304),
    (12, 28, 2368),
    (12, 29, 2432),
    (12, 30, 2496),
    (12, 31, 2560),
];
pub const BLACK_CODES: &[(u8, u16, u16)] = &[
    (10, 55, 0),
    (3, 2, 1),
    (2, 3, 2),
    (2, 2, 3),
    (3, 3, 4),
    (4, 3, 5),
    (4, 2, 6),
    (5, 3, 7),
    (6, 5, 8),
    (6, 4, 9),
    (7, 4, 10),
    (7, 5, 11),
    (7, 7, 12),
    (8, 4, 13),
    (8, 7, 14),
    (9, 24, 15),
    (10, 23, 16),
    (10, 24, 17),
    (10, 8, 18),
    (11, 103, 19),
    (11, 104, 20),
    (11, 108, 21),
    (11, 55, 22),
    (11, 40, 23),
    (11, 23, 24),
    (11, 24, 25),
    (12, 202, 26),
    (12, 203, 27),
    (12, 204, 28),
    (12, 205, 29),
    (12, 104, 30),
    (12, 105, 31),
    (12, 106, 32),
    (12, 107, 33),
    (12, 210, 34),
    (12, 211, 35),
    (12, 212, 36),
    (12, 213, 37),
    (12, 214, 38),
    (12, 215, 39),
    (12, 108, 40),
    (12, 109, 41),
    (12, 218, 42),
    (12, 219, 43),
    (12, 84, 44),
    (12, 85, 45),
    (12, 86, 46),
    (12, 87, 47),
    (12, 100, 48),
    (12, 101, 49),
    (12, 82, 50),
    (12, 83, 51),
    (12, 36, 52),
    (12, 55, 53),
    (12, 56, 54),
    (12, 39, 55),
    (12, 40, 56),
    (12, 88, 57),
    (12, 89, 58),
    (12, 43, 59),
    (12, 44, 60),
    (12, 90, 61),
    (12, 102, 62),
    (12, 103, 63),
    (10, 15, 64),
    (12, 200, 128),
    (12, 201, 192),
    (12, 91, 256),
    (12, 51, 320),
    (12, 52, 384),
    (12, 53, 448),
    (13, 108, 512),
    (13, 109, 576),
    (13, 74, 640),
    (13, 75, 704),
    (13, 76, 768),
    (13, 77, 832),
    (13, 114, 896),
    (13, 115, 960),
    (13, 116, 1024),
    (13, 117, 1088),
    (13, 118, 1152),
    (13, 119, 1216),
    (13, 82, 1280),
    (13, 83, 1344),
    (13, 84, 1408),
    (13, 85, 1472),
    (13, 90, 1536),
    (13, 91, 1600),
    (13, 100, 1664),
    (13, 101, 1728),
    (11, 8, 1792),
    (11, 12, 1856),
    (11, 13, 1920),
    (12, 18, 1984),
    (12, 19, 2048),
    (12, 20, 2112),
    (12, 21, 2176),
    (12, 22, 2240),
    (12, 23, 2304),
    (12, 28, 2368),
    (12, 29, 2432),
    (12, 30, 2496),
    (12, 31, 2560),
];

const MODE_V0: u8 = 0;
const MODE_VR1: u8 = 1;
const MODE_VR2: u8 = 2;
const MODE_VR3: u8 = 3;
const MODE_VL1: u8 = 4;
const MODE_VL2: u8 = 5;
const MODE_VL3: u8 = 6;
const MODE_H: u8 = 7;
const MODE_P: u8 = 8;

fn read_mode(bits: &[u8], pos: &mut usize) -> Option<u8> {
    let mut v = 0u16;
    let mut taken = 0usize;
    while taken < 7 {
        let idx = *pos + taken;
        if idx >= bits.len() {
            return None;
        }
        v = (v << 1) | u16::from(bits[idx]);
        taken += 1;
        let mode = match (taken, v) {
            (1, 0b1) => Some(MODE_V0),
            (3, 0b011) => Some(MODE_VR1),
            (3, 0b010) => Some(MODE_VL1),
            (6, 0b000011) => Some(MODE_VR2),
            (6, 0b000010) => Some(MODE_VL2),
            (7, 0b0000011) => Some(MODE_VR3),
            (7, 0b0000010) => Some(MODE_VL3),
            (3, 0b001) => Some(MODE_H),
            (4, 0b0001) => Some(MODE_P),
            _ => None,
        };
        if let Some(m) = mode {
            *pos += taken;
            return Some(m);
        }
    }
    None
}

fn read_mh_run(bits: &[u8], pos: &mut usize, white: bool) -> Result<u32, String> {
    let table: &[(u8, u16, u16)] = if white { WHITE_CODES } else { BLACK_CODES };
    let mut total: u32 = 0;
    loop {
        let mut v = 0u16;
        let mut taken = 0usize;
        let mut run: Option<u16> = None;
        while taken < 13 {
            let idx = *pos + taken;
            if idx >= bits.len() {
                return Err("EOF inside MH code".into());
            }
            v = (v << 1) | u16::from(bits[idx]);
            taken += 1;
            if let Some(&(_, _, r)) = table.iter().find(|e| e.0 as usize == taken && e.1 == v) {
                run = Some(r);
                break;
            }
        }
        let Some(run) = run else {
            return Err(format!("invalid MH code at bit {pos} (white={white})"));
        };
        *pos += taken;
        total += u32::from(run);
        if run <= 63 {
            return Ok(total);
        }
    }
}

fn fill(row: &mut Vec<u8>, start: isize, end: isize, color: u8, width: usize) {
    let start = start.max(0) as usize;
    let end = end.clamp(0, width as isize) as usize;
    if start >= end {
        return;
    }
    if row.len() < end {
        row.resize(end, 0);
    }
    row[start..end].fill(color);
}

fn find_b(reference: &[u8], a0: isize, color: u8, width: usize) -> (usize, usize) {
    let mut i = a0.max(0) as usize;
    while i < width && reference[i] == color {
        i += 1;
    }
    if i >= width {
        return (width, width);
    }
    let b1 = i;
    while i < width && reference[i] != color {
        i += 1;
    }
    (b1, i)
}

fn next_eol_pos(bits: &[u8], from: usize) -> Option<usize> {
    let mut v = 0u16;
    let mut seen = 0usize;
    let mut p = from;
    while seen < 12 {
        if p >= bits.len() {
            return None;
        }
        v = (v << 1) | u16::from(bits[p]);
        seen += 1;
        p += 1;
    }
    while v != 0x001 {
        if p >= bits.len() {
            return None;
        }
        v = ((v << 1) & 0x0FFF) | u16::from(bits[p]);
        p += 1;
    }
    Some(p)
}

pub fn decode_t4_pages(data: &[u8], width: usize) -> Result<Vec<FaxPage>, String> {
    let mut bits: Vec<u8> = Vec::with_capacity(data.len() * 8);
    for byte in data {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1);
        }
    }
    let nbits = bits.len();
    let eolpat: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

    let mut eols: Vec<usize> = Vec::new();
    let mut i = 0;
    while i + 12 <= nbits {
        if bits[i..i + 12] == eolpat {
            eols.push(i);
            i += 12;
        } else {
            i += 1;
        }
    }
    if eols.is_empty() {
        return Err("no EOL found in T.4 data".into());
    }

    let mut rtc_ends: Vec<usize> = Vec::new();
    let mut run_start = 0usize;
    for k in 1..eols.len() {
        if eols[k] - eols[k - 1] != 13 {
            if k - run_start >= 5 {
                rtc_ends.push(eols[k - 1]);
            }
            run_start = k;
        }
    }
    if eols.len() - run_start >= 5 {
        rtc_ends.push(eols[eols.len() - 1]);
    }

    let mut last_err = Err("no EOL found in T.4 data".to_string());
    for &start_eol in eols.iter().take(8) {
        match decode_from(&bits, &eols, &rtc_ends, start_eol + 12, width) {
            Ok(pages) => return Ok(pages),
            Err(e) => last_err = Err(e),
        }
    }
    last_err
}

fn decode_from(
    bits: &[u8],
    eols: &[usize],
    rtc_ends: &[usize],
    first_pos: usize,
    width: usize,
) -> Result<Vec<FaxPage>, String> {
    let nbits = bits.len();
    let eolpat: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let mut pos = first_pos;
    let mut pages: Vec<FaxPage> = Vec::new();
    let mut rows: VecDeque<Vec<u8>> = VecDeque::new();
    let mut reference: Vec<u8> = vec![0u8; width];
    let mut consecutive_eols = 1usize;
    let mut guard = 0usize;

    'page: loop {
        guard += 1;
        if guard > 100_000 {
            return Err("decode runaway".into());
        }
        if pos >= nbits {
            break;
        }
        let one_d = bits[pos] == 1;
        pos += 1;
        if pos + 12 <= nbits && bits[pos..pos + 12] == eolpat {
            consecutive_eols += 1;
            if consecutive_eols >= 6 {
                if !rows.is_empty() {
                    pages.push(FaxPage {
                        width,
                        height: rows.len(),
                        rows: rows.into(),
                    });
                    rows = VecDeque::new();
                }
                let next_rtc = rtc_ends.iter().copied().find(|&e| e + 12 > pos - 12);
                let next_page_eol = match next_rtc {
                    Some(rtc_end) => eols.iter().copied().find(|&e| e > rtc_end + 13),
                    None => None,
                };
                match next_page_eol {
                    Some(e) => {
                        reference = vec![0u8; width];
                        consecutive_eols = 1;
                        pos = e + 12;
                        continue;
                    }
                    None => break 'page,
                }
            }
            pos += 12;
            continue;
        }

        let mut row: Vec<u8> = Vec::with_capacity(width);
        if one_d {
            let mut white = true;
            while row.len() < width {
                match read_mh_run(bits, &mut pos, white) {
                    Ok(run) => {
                        let run = run.min((width - row.len()) as u32);
                        let pixel = if white { 0u8 } else { 1u8 };
                        row.extend(std::iter::repeat_n(pixel, run as usize));
                    }
                    Err(_) => {
                        row.extend_from_slice(&reference[row.len()..]);
                        pos = next_eol_pos(bits, pos).unwrap_or(nbits);
                        break;
                    }
                }
                white = !white;
            }
        } else {
            let mut a0: isize = -1;
            let mut start: usize = 0;
            let mut color: u8 = 0;
            let mut steps = 0usize;
            while a0 < width as isize {
                steps += 1;
                if steps > 10_000 {
                    return Err(format!("2D line decode runaway (page {})", pages.len()));
                }
                let save = pos;
                let mode = match read_mode(bits, &mut pos) {
                    Some(m) => m,
                    None => {
                        pos = save;
                        row.extend_from_slice(&reference[row.len()..]);
                        break;
                    }
                };
                match mode {
                    MODE_P => {
                        let (_, b2) = find_b(&reference, a0, color, width);
                        fill(&mut row, start as isize, b2 as isize, color, width);
                        a0 = b2 as isize;
                        start = b2;
                    }
                    MODE_H => {
                        let (r1, r2) = match (
                            read_mh_run(bits, &mut pos, color == 0),
                            read_mh_run(bits, &mut pos, color != 0),
                        ) {
                            (Ok(a), Ok(b)) => (a, b),
                            _ => {
                                row.extend_from_slice(&reference[row.len()..]);
                                pos = next_eol_pos(bits, pos).unwrap_or(nbits);
                                break;
                            }
                        };
                        let a1 = start + r1 as usize;
                        fill(&mut row, start as isize, a1 as isize, color, width);
                        let a2 = a1 + r2 as usize;
                        fill(&mut row, a1 as isize, a2 as isize, 1 - color, width);
                        a0 = a2 as isize;
                        start = a2;
                    }
                    m => {
                        let delta = match m {
                            MODE_VR1 => 1,
                            MODE_VR2 => 2,
                            MODE_VR3 => 3,
                            MODE_VL1 => -1,
                            MODE_VL2 => -2,
                            MODE_VL3 => -3,
                            _ => 0,
                        };
                        let (b1, _) = find_b(&reference, a0, color, width);
                        let a1 = b1 as isize + delta;
                        fill(&mut row, start as isize, a1, color, width);
                        a0 = a1;
                        start = a1.max(0) as usize;
                        color = 1 - color;
                    }
                }
            }
        }

        if row.len() < width {
            row.resize(width, 0);
        }
        reference = row.clone();
        rows.push_back(row);

        let mut v = 0u16;
        let mut seen = 0usize;
        while seen < 12 {
            if pos >= nbits {
                break 'page;
            }
            v = (v << 1) | u16::from(bits[pos]);
            seen += 1;
            pos += 1;
        }
        while seen == 12 && v != 0x001 {
            if pos >= nbits {
                break 'page;
            }
            v = ((v << 1) & 0x0FFF) | u16::from(bits[pos]);
            pos += 1;
        }
        consecutive_eols = 1;
    }

    if !rows.is_empty() {
        pages.push(FaxPage {
            width,
            height: rows.len(),
            rows: rows.into(),
        });
    }
    Ok(pages)
}

pub fn to_pbm(page: &FaxPage) -> Vec<u8> {
    let mut out = format!("P4\n{} {}\n", page.width, page.height).into_bytes();
    let stride = page.width.div_ceil(8);
    for row in &page.rows {
        let mut packed = vec![0u8; stride];
        for (i, &p) in row.iter().enumerate() {
            if p != 0 {
                packed[i / 8] |= 0x80 >> (i % 8);
            }
        }
        out.extend_from_slice(&packed);
    }
    out
}
