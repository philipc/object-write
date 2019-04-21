use std::iter;

pub(crate) fn align(offset: usize, size: usize) -> usize {
    (offset + (size - 1)) & !(size - 1)
}

pub(crate) fn write_align(buffer: &mut Vec<u8>, size: usize) {
    let prev_offset = buffer.len();
    let offset = align(prev_offset, size);
    buffer.extend(iter::repeat(0).take(offset - prev_offset));
}
