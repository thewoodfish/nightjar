// Copyright 2026 Algorealm, Inc.
// This file is part of Nightjar.
// Nightjar is free software: you can redistribute it and/or modify
// it under the terms of Apache 2.0 License as published by the Apache Software Foundation.

//! JAM deserialization — inverse of the E functions in Appendix C.

use crate::error::CodecError;

/// A cursor over a byte slice for decoding.
pub struct Decoder<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    /// Read exactly `n` bytes.
    pub fn read_bytes(&mut self, n: usize) -> Result<&[u8], CodecError> {
        if self.remaining() < n {
            return Err(CodecError::BufferTooShort {
                needed: n,
                available: self.remaining(),
            });
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    /// Read a single byte.
    pub fn read_u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.read_bytes(1)?[0])
    }

    /// Read 2 bytes as u16 little-endian. E2^{-1}.
    pub fn read_u16(&mut self) -> Result<u16, CodecError> {
        let b = self.read_bytes(2)?;
        Ok(u16::from_le_bytes(b.try_into().unwrap()))
    }

    /// Read 4 bytes as u32 little-endian. E4^{-1}.
    pub fn read_u32(&mut self) -> Result<u32, CodecError> {
        let b = self.read_bytes(4)?;
        Ok(u32::from_le_bytes(b.try_into().unwrap()))
    }

    /// Read 8 bytes as u64 little-endian. E8^{-1}.
    pub fn read_u64(&mut self) -> Result<u64, CodecError> {
        let b = self.read_bytes(8)?;
        Ok(u64::from_le_bytes(b.try_into().unwrap()))
    }

    /// Read a 32-byte hash.
    pub fn read_hash(&mut self) -> Result<[u8; 32], CodecError> {
        Ok(self.read_bytes(32)?.try_into().unwrap())
    }

    /// Read a 96-byte Bandersnatch signature.
    pub fn read_bandersnatch_sig(&mut self) -> Result<[u8; 96], CodecError> {
        Ok(self.read_bytes(96)?.try_into().unwrap())
    }

    /// Read a 32-byte Ed25519 public key.
    pub fn read_ed25519_public(&mut self) -> Result<[u8; 32], CodecError> {
        Ok(self.read_bytes(32)?.try_into().unwrap())
    }

    /// Decode a variable-length natural number. E^{-1}.
    /// Appendix C.1.1, Equation C.5.
    pub fn read_natural(&mut self) -> Result<u64, CodecError> {
        let prefix = self.read_u8()?;

        if prefix == 0x00 {
            return Ok(0);
        }

        if prefix == 0xFF {
            return self.read_u64();
        }

        // Determine l from prefix
        // prefix = 2^8 - 2^(8-l) + high_bits
        // Leading ones in the prefix indicate l
        let l = prefix.leading_ones() as usize;

        // Mask off the leading ones to get high bits
        let high_mask = 0xFFu8 >> (l + 1);
        let high = (prefix & high_mask) as u64;

        // Read l more bytes for the low part
        let mut low = 0u64;
        for i in 0..l {
            let byte = self.read_u8()? as u64;
            low |= byte << (8 * i);
        }

        Ok((high << (8 * l)) | low)
    }

    /// Decode a length-prefixed byte sequence. ↕^{-1}.
    /// Appendix C.1.3.
    pub fn read_length_prefixed(&mut self) -> Result<Vec<u8>, CodecError> {
        let len = self.read_natural()? as usize;
        Ok(self.read_bytes(len)?.to_vec())
    }

    /// Decode an optional value. ¿^{-1}.
    /// Appendix C.1.3.
    pub fn read_optional<T, F>(&mut self, decode: F) -> Result<Option<T>, CodecError>
    where
        F: FnOnce(&mut Self) -> Result<T, CodecError>,
    {
        let discriminator = self.read_u8()?;
        match discriminator {
            0 => Ok(None),
            1 => Ok(Some(decode(self)?)),
            b => Err(CodecError::InvalidDiscriminator {
                byte: b,
                offset: self.pos - 1,
            }),
        }
    }

    /// Decode a sequence of n fixed-size items.
    pub fn read_sequence_fixed<T, F>(
        &mut self,
        count: usize,
        decode_item: F,
    ) -> Result<Vec<T>, CodecError>
    where
        F: Fn(&mut Self) -> Result<T, CodecError>,
    {
        let mut items = Vec::with_capacity(count);
        for _ in 0..count {
            items.push(decode_item(self)?);
        }
        Ok(items)
    }

    /// Decode a length-prefixed sequence.
    pub fn read_sequence_length_prefixed<T, F>(
        &mut self,
        decode_item: F,
    ) -> Result<Vec<T>, CodecError>
    where
        F: Fn(&mut Self) -> Result<T, CodecError>,
    {
        let count = self.read_natural()? as usize;
        self.read_sequence_fixed(count, decode_item)
    }
}