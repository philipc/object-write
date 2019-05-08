pub(crate) fn align(offset: usize, size: usize) -> usize {
    (offset + (size - 1)) & !(size - 1)
}

pub(crate) fn write_align(buffer: &mut Vec<u8>, size: usize) {
    let offset = align(buffer.len(), size);
    buffer.resize(offset, 0);
}
