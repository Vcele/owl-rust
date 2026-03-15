// Buffer abstraction layer for packet I/O

use std::fmt;

/// Error type for wire/buffer operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    OutOfBounds,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::OutOfBounds => write!(f, "Out of bounds"),
        }
    }
}

impl std::error::Error for WireError {}

/// Buffer abstraction for safe packet reading and writing.
///
/// Supports a window (start..end) over an underlying byte vector,
/// allowing strip (remove from front) and take (remove from back)
/// operations without copying data.
#[derive(Debug, Clone)]
pub struct Buf {
    data: Vec<u8>,
    start: usize,
    end: usize,
}

impl Buf {
    /// Create a new zeroed owned buffer of `len` bytes
    pub fn new(len: usize) -> Self {
        Buf {
            data: vec![0u8; len],
            start: 0,
            end: len,
        }
    }

    /// Create a buffer from an existing byte vector
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        let len = bytes.len();
        Buf {
            data: bytes,
            start: 0,
            end: len,
        }
    }

    /// Create a buffer from a byte slice (copies data)
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self::from_bytes(bytes.to_vec())
    }

    /// Get a reference to the active window of the buffer
    pub fn data(&self) -> &[u8] {
        &self.data[self.start..self.end]
    }

    /// Get a mutable reference to the active window of the buffer
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.data[self.start..self.end]
    }

    /// Length of the active window
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    /// Whether the active window is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Strip `len` bytes from the front of the buffer
    pub fn strip(&mut self, len: usize) -> Result<(), WireError> {
        if len > self.len() {
            return Err(WireError::OutOfBounds);
        }
        self.start += len;
        Ok(())
    }

    /// Strip `len` bytes from the end of the buffer
    pub fn take(&mut self, len: usize) -> Result<(), WireError> {
        if len > self.len() {
            return Err(WireError::OutOfBounds);
        }
        self.end -= len;
        Ok(())
    }

    fn check_bounds(&self, offset: usize, size: usize) -> Result<(), WireError> {
        if offset.saturating_add(size) > self.len() {
            Err(WireError::OutOfBounds)
        } else {
            Ok(())
        }
    }

    // --- Read functions ---

    pub fn read_u8(&self, offset: usize) -> Result<u8, WireError> {
        self.check_bounds(offset, 1)?;
        Ok(self.data[self.start + offset])
    }

    pub fn read_le16(&self, offset: usize) -> Result<u16, WireError> {
        self.check_bounds(offset, 2)?;
        let b = &self.data[self.start + offset..];
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn read_be16(&self, offset: usize) -> Result<u16, WireError> {
        self.check_bounds(offset, 2)?;
        let b = &self.data[self.start + offset..];
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn read_le32(&self, offset: usize) -> Result<u32, WireError> {
        self.check_bounds(offset, 4)?;
        let b = &self.data[self.start + offset..];
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn read_be32(&self, offset: usize) -> Result<u32, WireError> {
        self.check_bounds(offset, 4)?;
        let b = &self.data[self.start + offset..];
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Read a 6-byte Ethernet MAC address
    pub fn read_ether_addr(&self, offset: usize) -> Result<[u8; 6], WireError> {
        self.check_bounds(offset, 6)?;
        let b = &self.data[self.start + offset..];
        Ok([b[0], b[1], b[2], b[3], b[4], b[5]])
    }

    /// Read a reference to `length` bytes at `offset`
    pub fn read_bytes(&self, offset: usize, length: usize) -> Result<&[u8], WireError> {
        self.check_bounds(offset, length)?;
        Ok(&self.data[self.start + offset..self.start + offset + length])
    }

    /// Read and copy `length` bytes at `offset` into `dest`
    pub fn read_bytes_copy(&self, offset: usize, dest: &mut [u8]) -> Result<(), WireError> {
        let length = dest.len();
        self.check_bounds(offset, length)?;
        dest.copy_from_slice(&self.data[self.start + offset..self.start + offset + length]);
        Ok(())
    }

    /// Read a length-prefixed string (1-byte length prefix)
    pub fn read_int_string(&self, offset: usize, max_len: usize) -> Result<(String, usize), WireError> {
        let raw_len = self.read_u8(offset)? as usize;
        let actual_len = raw_len.min(max_len);
        let bytes = self.read_bytes(offset + 1, actual_len)?;
        let s = String::from_utf8_lossy(bytes).to_string();
        // Return the true wire-format length (raw_len + 1 byte for the length field)
        Ok((s, raw_len + 1))
    }

    /// Read a TLV (Type-Length-Value) entry.
    /// Returns `(type, value_bytes, next_offset)`.
    pub fn read_tlv(&self, offset: usize) -> Result<(u8, &[u8], usize), WireError> {
        let tlv_type = self.read_u8(offset)?;
        let tlv_len = self.read_le16(offset + 1)? as usize;
        let val = self.read_bytes(offset + 3, tlv_len)?;
        Ok((tlv_type, val, offset + 3 + tlv_len))
    }

    // --- Write functions ---

    pub fn write_u8(&mut self, offset: usize, value: u8) -> Result<(), WireError> {
        self.check_bounds(offset, 1)?;
        self.data[self.start + offset] = value;
        Ok(())
    }

    pub fn write_le16(&mut self, offset: usize, value: u16) -> Result<(), WireError> {
        self.check_bounds(offset, 2)?;
        let bytes = value.to_le_bytes();
        self.data[self.start + offset..self.start + offset + 2].copy_from_slice(&bytes);
        Ok(())
    }

    pub fn write_be16(&mut self, offset: usize, value: u16) -> Result<(), WireError> {
        self.check_bounds(offset, 2)?;
        let bytes = value.to_be_bytes();
        self.data[self.start + offset..self.start + offset + 2].copy_from_slice(&bytes);
        Ok(())
    }

    pub fn write_le32(&mut self, offset: usize, value: u32) -> Result<(), WireError> {
        self.check_bounds(offset, 4)?;
        let bytes = value.to_le_bytes();
        self.data[self.start + offset..self.start + offset + 4].copy_from_slice(&bytes);
        Ok(())
    }

    pub fn write_be32(&mut self, offset: usize, value: u32) -> Result<(), WireError> {
        self.check_bounds(offset, 4)?;
        let bytes = value.to_be_bytes();
        self.data[self.start + offset..self.start + offset + 4].copy_from_slice(&bytes);
        Ok(())
    }

    pub fn write_ether_addr(&mut self, offset: usize, addr: &[u8; 6]) -> Result<(), WireError> {
        self.check_bounds(offset, 6)?;
        self.data[self.start + offset..self.start + offset + 6].copy_from_slice(addr);
        Ok(())
    }

    pub fn write_bytes(&mut self, offset: usize, bytes: &[u8]) -> Result<(), WireError> {
        let length = bytes.len();
        self.check_bounds(offset, length)?;
        self.data[self.start + offset..self.start + offset + length].copy_from_slice(bytes);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Buf::take ---

    #[test]
    fn test_buf_take() {
        let mut frame = Buf::new(2);
        frame.write_u8(0, 4).unwrap();
        frame.write_u8(1, 2).unwrap();
        frame.take(1).unwrap();
        assert_eq!(frame.len(), 1);
        assert_eq!(frame.read_u8(0).unwrap(), 4);
    }

    #[test]
    fn test_buf_take_oob() {
        let mut frame = Buf::new(1);
        assert!(frame.take(frame.len() + 1).is_err());
        assert_eq!(frame.len(), 1);
    }

    // --- Buf::strip ---

    #[test]
    fn test_buf_strip() {
        let mut frame = Buf::new(2);
        frame.write_u8(0, 4).unwrap();
        frame.write_u8(1, 2).unwrap();
        frame.strip(1).unwrap();
        assert_eq!(frame.len(), 1);
        assert_eq!(frame.read_u8(0).unwrap(), 2);
    }

    #[test]
    fn test_buf_strip_oob() {
        let mut frame = Buf::new(1);
        assert!(frame.strip(frame.len() + 1).is_err());
        assert_eq!(frame.len(), 1);
    }

    // --- read_u8 ---

    #[test]
    fn test_read_u8_valid() {
        let frame = Buf::new(1);
        assert!(frame.read_u8(0).is_ok());
    }

    #[test]
    fn test_read_u8_oob() {
        let frame = Buf::new(1);
        assert!(frame.read_u8(1).is_err());
    }

    // --- read/write round-trips ---

    #[test]
    fn test_read_write_u8() {
        let mut frame = Buf::new(1);
        frame.write_u8(0, 0xab).unwrap();
        assert_eq!(frame.read_u8(0).unwrap(), 0xab);
    }

    #[test]
    fn test_read_write_le16() {
        let mut frame = Buf::new(2);
        frame.write_le16(0, 0x1234).unwrap();
        assert_eq!(frame.read_le16(0).unwrap(), 0x1234);
        // also verify byte order
        assert_eq!(frame.data()[0], 0x34);
        assert_eq!(frame.data()[1], 0x12);
    }

    #[test]
    fn test_read_write_be16() {
        let mut frame = Buf::new(2);
        frame.write_be16(0, 0x1234).unwrap();
        assert_eq!(frame.read_be16(0).unwrap(), 0x1234);
        // verify big-endian byte order
        assert_eq!(frame.data()[0], 0x12);
        assert_eq!(frame.data()[1], 0x34);
    }

    #[test]
    fn test_read_write_le32() {
        let mut frame = Buf::new(4);
        frame.write_le32(0, 0xdeadbeef).unwrap();
        assert_eq!(frame.read_le32(0).unwrap(), 0xdeadbeef);
    }

    #[test]
    fn test_read_write_be32() {
        let mut frame = Buf::new(4);
        frame.write_be32(0, 0xdeadbeef).unwrap();
        assert_eq!(frame.read_be32(0).unwrap(), 0xdeadbeef);
        assert_eq!(frame.data()[0], 0xde);
    }

    #[test]
    fn test_read_write_ether_addr() {
        let mut frame = Buf::new(6);
        let addr = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        frame.write_ether_addr(0, &addr).unwrap();
        assert_eq!(frame.read_ether_addr(0).unwrap(), addr);
    }

    #[test]
    fn test_read_le16_oob() {
        let frame = Buf::new(2);
        assert!(frame.read_le16(1).is_err());
        assert!(frame.read_le16(0).is_ok());
    }

    #[test]
    fn test_read_bytes() {
        let mut frame = Buf::new(4);
        frame.write_bytes(0, &[1, 2, 3, 4]).unwrap();
        assert_eq!(frame.read_bytes(0, 4).unwrap(), &[1, 2, 3, 4]);
        assert_eq!(frame.read_bytes(2, 2).unwrap(), &[3, 4]);
        assert!(frame.read_bytes(3, 2).is_err());
    }

    #[test]
    fn test_read_tlv() {
        // type=0x01, length=3 (LE16), value=[0xaa, 0xbb, 0xcc]
        let mut frame = Buf::new(6);
        frame.write_u8(0, 0x01).unwrap();         // type
        frame.write_le16(1, 3).unwrap();           // length
        frame.write_bytes(3, &[0xaa, 0xbb, 0xcc]).unwrap(); // value
        let (t, v, next) = frame.read_tlv(0).unwrap();
        assert_eq!(t, 0x01);
        assert_eq!(v, &[0xaa, 0xbb, 0xcc]);
        assert_eq!(next, 6);
    }
}
