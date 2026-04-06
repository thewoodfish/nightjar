// Copyright 2026 Algorealm, Inc.
// This file is part of Nightjar.
// Nightjar is free software: you can redistribute it and/or modify
// it under the terms of Apache 2.0 License as published by the Apache Software Foundation.

//! Header serialization — Appendix C.2 of the Graypaper v0.7.2.
//!
//! Two encodings are defined:
//!
//! E(H)  = E(EU(H), HS)        — full header including seal
//! EU(H) = E(HP, HR, HX, E4(HT), ¿HE, ¿HW, E2(HI), HV, ↕HO)
//!                              — unsigned header (what the seal signs)
//!
//! Equations C.22, C.23.

use crate::{decode::Decoder, encode::*, error::CodecError};
use nightjar_types::header::{EpochMarker, Header, Ticket, ValidatorKeyPair};

/// Encode the unsigned header EU(H).
///
/// Equation C.23:
/// EU(H) = E(HP, HR, HX, E4(HT), ¿HE, ¿HW, E2(HI), HV, ↕HO)
///
/// This is what the block seal HS signs. Everything except HS itself.
pub fn encode_header_unsigned(header: &Header) -> Vec<u8> {
    let mut out = Vec::new();

    // HP — parent hash (32 bytes, identity encoding)
    encode_bytes(&header.parent_hash, &mut out);

    // HR — prior state root (32 bytes)
    encode_bytes(&header.prior_state_root, &mut out);

    // HX — extrinsic hash (32 bytes)
    encode_bytes(&header.extrinsic_hash, &mut out);

    // HT — timeslot as E4 (4 bytes little-endian)
    // Equation C.23: E4(HT)
    encode_u32(header.time_slot, &mut out);

    // HE — epoch marker, optional: ¿HE
    // Equation C.23: ¿HE
    match &header.epoch_marker {
        None => out.push(0x00),
        Some(marker) => {
            out.push(0x01);
            encode_epoch_marker(marker, &mut out);
        }
    }

    // HW — winning tickets, optional: ¿HW
    // Equation C.23: ¿HW
    match &header.winning_tickets {
        None => out.push(0x00),
        Some(tickets) => {
            out.push(0x01);
            // Encode as a length-prefixed sequence of tickets
            encode_sequence_length_prefixed(tickets, encode_ticket, &mut out);
        }
    }

    // HI — author index as E2 (2 bytes little-endian)
    // Equation C.23: E2(HI)
    encode_u16(header.author_index, &mut out);

    // HV — entropy source VRF signature (96 bytes)
    encode_bytes(&header.entropy_source, &mut out);

    // HO — offenders mark, length-prefixed sequence of Ed25519 keys
    // Equation C.23: ↕HO
    encode_sequence_length_prefixed(
        &header.offenders_mark,
        |key, out| encode_bytes(key, out),
        &mut out,
    );

    out
}

/// Encode the full header E(H) including the seal.
///
/// Equation C.22: E(H) = E(EU(H), HS)
pub fn encode_header(header: &Header) -> Vec<u8> {
    let mut out = encode_header_unsigned(header);
    // HS — seal appended after unsigned portion
    encode_bytes(&header.seal, &mut out);
    out
}

/// Encode an epoch marker.
/// Equation 6.27: (η0, η1, [(kb, ke) | k ← γ'P])
fn encode_epoch_marker(marker: &EpochMarker, out: &mut Vec<u8>) {
    encode_bytes(&marker.entropy, out);
    encode_bytes(&marker.entropy_prev, out);
    encode_sequence_length_prefixed(&marker.validator_keys, encode_validator_key_pair, out);
}

/// Encode a validator key pair (kb, ke).
fn encode_validator_key_pair(pair: &ValidatorKeyPair, out: &mut Vec<u8>) {
    encode_bytes(&pair.bandersnatch, out); // 32 bytes
    encode_bytes(&pair.ed25519, out); // 32 bytes
}

/// Encode a single ticket (y, e).
/// Equation 6.6: T ≡ {y ∈ H, e ∈ NN}
/// Equation C.30: E(x ∈ T) ≡ E(xy, xe)
fn encode_ticket(ticket: &Ticket, out: &mut Vec<u8>) {
    encode_bytes(&ticket.id, out); // y — 32 bytes
    encode_u8(ticket.attempt, out); // e — 1 byte
}

// ── Decode ────────────────────────────────────────────────────────────────────

/// Decode a full header E^{-1}(H).
pub fn decode_header(data: &[u8]) -> Result<Header, CodecError> {
    let mut d = Decoder::new(data);
    decode_header_from(&mut d)
}

/// Decode a header from a decoder cursor.
pub fn decode_header_from(d: &mut Decoder) -> Result<Header, CodecError> {
    let parent_hash = d.read_hash()?;
    let prior_state_root = d.read_hash()?;
    let extrinsic_hash = d.read_hash()?;
    let time_slot = d.read_u32()?;

    let epoch_marker = d.read_optional(decode_epoch_marker)?;
    let winning_tickets = d.read_optional(|d| d.read_sequence_length_prefixed(decode_ticket))?;

    let author_index = d.read_u16()?;
    let entropy_source = d.read_bandersnatch_sig()?;

    let offenders_mark = d.read_sequence_length_prefixed(|d| d.read_ed25519_public())?;

    let seal = d.read_bandersnatch_sig()?;

    Ok(Header {
        parent_hash,
        prior_state_root,
        extrinsic_hash,
        time_slot,
        epoch_marker,
        winning_tickets,
        offenders_mark,
        author_index,
        entropy_source,
        seal,
    })
}

fn decode_epoch_marker(d: &mut Decoder) -> Result<EpochMarker, CodecError> {
    let entropy = d.read_hash()?;
    let entropy_prev = d.read_hash()?;
    let validator_keys = d.read_sequence_length_prefixed(|d| {
        let bandersnatch = d.read_bytes(32)?.try_into().unwrap();
        let ed25519 = d.read_ed25519_public()?;
        Ok(ValidatorKeyPair {
            bandersnatch,
            ed25519,
        })
    })?;
    Ok(EpochMarker {
        entropy,
        entropy_prev,
        validator_keys,
    })
}

fn decode_ticket(d: &mut Decoder) -> Result<Ticket, CodecError> {
    let id = d.read_hash()?;
    let attempt = d.read_u8()?;
    Ok(Ticket { id, attempt })
}
