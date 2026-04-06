// Copyright 2026 Algorealm, Inc.
// This file is part of Nightjar.
// Nightjar is free software: you can redistribute it and/or modify
// it under the terms of Apache 2.0 License as published by the Apache Software Foundation

//! JAM serialization codec — Appendix C of the Graypaper v0.7.2.
//!
//! Implements the E (encode) family of functions defined in Appendix C.
//! All encoding is into a Vec<u8> output buffer.

// ── Fixed-length integer encoding ────────────────────────────────────────────
//
// Appendix C.1.7:
// El(x) encodes x as l octets in little-endian order.
// "Values are encoded in a regular little-endian fashion."

/// Encode a u8 as 1 byte. E1.
/// Appendix C.1.7.
pub fn encode_u8(val: u8, out: &mut Vec<u8>) {
    out.push(val);
}

/// Encode a u16 as 2 bytes little-endian. E2.
/// Appendix C.1.7.
pub fn encode_u16(val: u16, out: &mut Vec<u8>) {
    out.extend_from_slice(&val.to_le_bytes());
}

/// Encode a u32 as 4 bytes little-endian. E4.
/// Appendix C.1.7.
pub fn encode_u32(val: u32, out: &mut Vec<u8>) {
    out.extend_from_slice(&val.to_le_bytes());
}

/// Encode a u64 as 8 bytes little-endian. E8.
/// Appendix C.1.7.
pub fn encode_u64(val: u64, out: &mut Vec<u8>) {
    out.extend_from_slice(&val.to_le_bytes());
}

/// Encode a fixed-size byte slice as-is (identity encoding).
/// Appendix C.1.1: E(x ∈ B) ≡ x
pub fn encode_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(bytes);
}

// ── General natural number encoding ──────────────────────────────────────────
//
// Appendix C.1.1, Equation C.5:
// Variable-length encoding for naturals up to 2^64.
//
// The encoding uses a prefix byte to signal how many additional
// bytes follow:
//   - 0x00            → value 0
//   - 0x01..=0x3F     → 1-byte value (6 bits of data in prefix)
//   - 0x40..=0x7F     → 2-byte value
//   - 0x80..=0xBF     → 4-byte value
//   - 0xC0..=0xFE     → 8-byte value  
//   - 0xFF            → 8-byte value follows directly (full u64)
//
// Formally: x ↦ [2^8 - 2^(8-l) + ⌊x / 2^(8l)⌋] ⌢ El(x mod 2^(8l))
// where l is chosen such that 2^(7l) ≤ x < 2^(7(l+1))

/// Encode a natural number with variable-length encoding.
/// Appendix C.1.1, Equation C.5.
///
/// Encoding ranges:
///   0         → [0x00]                    1 byte
///   1..127    → [val]                     1 byte  (l=0)
///   128..16383→ [0x80|(val>>8), val&0xFF] 2 bytes (l=1)
///   ...up to 8 bytes for large values
///   ≥2^56     → [0xFF, val as 8 LE bytes] 9 bytes
pub fn encode_natural(val: u64, out: &mut Vec<u8>) {
    if val == 0 {
        out.push(0x00);
        return;
    }

    // Find l: smallest value in 0..=7 such that val < 2^(7*(l+1))
    let l = (0usize..8)
        .find(|&l| val < (1u64 << (7 * (l + 1))))
        .unwrap_or(8);

    if l == 0 {
        // Single-byte encoding: the prefix IS the value.
        // prefix = 2^8 - 2^8 + val = val (for val in 1..=127)
        // No additional bytes follow.
        out.push(val as u8);
    } else if l == 8 {
        // Value >= 2^56: 9-byte encoding with 0xFF sentinel.
        out.push(0xFF);
        out.extend_from_slice(&val.to_le_bytes());
    } else {
        // l in 1..=7: prefix + l additional bytes.
        // prefix = 2^8 - 2^(8-l) + ⌊val / 2^(8l)⌋
        // Safe: l >= 1 so (8-l) <= 7, shift is always valid in u8 range.
        let prefix_base = 0xFFu8 - ((1u8) << (8 - l)) + 1;
        let high = (val >> (8 * l)) as u8;
        out.push(prefix_base | high);
        // Low l bytes in little-endian order.
        for i in 0..l {
            out.push((val >> (8 * i)) as u8);
        }
    }
}

// ── Discriminator encodings ───────────────────────────────────────────────────

/// Length-discriminated encoding: ↕x ≡ (|x|, x).
/// Appendix C.1.3, Equation C.7: E(↕x) ≡ E(|x|) ⌢ E(x)
///
/// Prefixes the byte slice with its length as a natural number,
/// then appends the bytes themselves.
pub fn encode_length_prefixed(bytes: &[u8], out: &mut Vec<u8>) {
    encode_natural(bytes.len() as u64, out);
    encode_bytes(bytes, out);
}

/// Optional encoding: ¿x ≡ 0 if x = ∅, else (1, x).
/// Appendix C.1.3, Equation C.8.
///
/// Encodes None as a single 0x00 byte.
/// Encodes Some(x) as 0x01 followed by the encoding of x.
pub fn encode_optional(
    val: Option<&[u8]>,
    out: &mut Vec<u8>,
) {
    match val {
        None => out.push(0x00),
        Some(bytes) => {
            out.push(0x01);
            encode_bytes(bytes, out);
        }
    }
}

/// Optional with a length prefix on the inner value.
/// Used for ¿HE and ¿HW in the header encoding (equation C.23).
pub fn encode_optional_length_prefixed(
    val: Option<&[u8]>,
    out: &mut Vec<u8>,
) {
    match val {
        None => out.push(0x00),
        Some(bytes) => {
            out.push(0x01);
            encode_length_prefixed(bytes, out);
        }
    }
}

// ── Sequence encoding ─────────────────────────────────────────────────────────

/// Encode a sequence of fixed-size items.
/// Appendix C.1.2: E([i0, i1, ...]) ≡ E(i0) ⌢ E(i1) ⌢ ...
///
/// Each item is encoded by the provided function.
pub fn encode_sequence<T, F>(items: &[T], encode_item: F, out: &mut Vec<u8>)
where
    F: Fn(&T, &mut Vec<u8>),
{
    for item in items {
        encode_item(item, out);
    }
}

/// Encode a sequence with a length prefix.
/// Used for variable-length sequences throughout the protocol.
pub fn encode_sequence_length_prefixed<T, F>(
    items: &[T],
    encode_item: F,
    out: &mut Vec<u8>,
) where
    F: Fn(&T, &mut Vec<u8>),
{
    encode_natural(items.len() as u64, out);
    for item in items {
        encode_item(item, out);
    }
}

// ── Bit sequence encoding ─────────────────────────────────────────────────────

/// Encode a bit sequence into packed octets, LSB first.
/// Appendix C.1.4, Equation C.9.
///
/// Bits are packed 8 per byte, least significant first.
/// The length must be known externally (or prefixed separately).
pub fn encode_bits(bits: &[bool], out: &mut Vec<u8>) {
    for chunk in bits.chunks(8) {
        let mut byte = 0u8;
        for (i, &bit) in chunk.iter().enumerate() {
            if bit {
                byte |= 1 << i;
            }
        }
        out.push(byte);
    }
}