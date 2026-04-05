// Copyright 2026 Algorealm, Inc.
// This file is part of Nightjar.
// Nightjar is free software: you can redistribute it and/or modify
// it under the terms of Apache 2.0 License as published by the Apache Software Foundation.

//! Primitive type aliases and constants used across the Nightjar codebase.
//! Directly traceavle to Greypaper v0.7.2 section references.


// ── Type Aliases ─────────────────────────────────────────────────────────────

/// A 32-byte cryptographic hash value.
/// Section 3.8.1: "H denotes the set of 256-bit values equivalent to B32"
pub type Hash = [u8; 32];

/// Zero hash H0.
/// Section 3.8.1.
pub const HASH_ZERO: Hash = [0u8; 32];

/// A Bandersnatch public key.
/// Section 3.8.2: H̃ ⊂ B32
pub type BandersnatchPublic = [u8; 32];

/// A Bandersnatch VRF/seal signature.
/// Section 3.8.2: ∽V ⊂ B96
pub type BandersnatchSignature = [u8; 96];

/// An Ed25519 public key.
/// Section 3.8.2: H̄ ⊂ B32
pub type Ed25519Public = [u8; 32];

/// An Ed25519 signature.
/// Section 3.8.2: V̄_k⟨m⟩ ⊂ B64
pub type Ed25519Signature = [u8; 64];

/// A BLS public key.
/// Section 3.8.2: BLS_B ⊂ B144
pub type BlsPublic = [u8; 144];

/// A timeslot index.
/// Equation 4.28: NT ≡ N_{2^32}
pub type TimeSlot = u32;

/// A validator index. Valid range: 0..V (exclusive), V = 1023.
/// Appendix I: V = 1023.
pub type ValidatorIndex = u16;

/// A service identifier.
/// Equation 9.1: NS ≡ N_{2^32}
pub type ServiceId = u32;

/// A balance value.
/// Equation 4.21: NB ≡ N_{2^64}
pub type Balance = u64;

/// A gas value (unsigned).
/// Equation 4.23: NG ≡ N_{2^64}
pub type Gas = u64;

/// A core index. Valid range: 0..C (exclusive), C = 341.
/// Appendix I: C = 341.
pub type CoreIndex = u16;

// ── Protocol Constants ───────────────────────────────────────────────────────

/// Slot period in seconds. P = 6.
/// Section 4.8.
pub const SLOT_PERIOD: u64 = 6;

/// Total number of validators. V = 1023.
/// Appendix I.
pub const VALIDATOR_COUNT: u32 = 1023;

/// Total number of cores. C = 341.
/// Appendix I.
pub const CORE_COUNT: u32 = 341;

/// Epoch length in slots. E = 600.
/// Section 4.8.
pub const EPOCH_LENGTH: u32 = 600;

/// Ticket submission ends at slot Y within an epoch. Y = 500.
/// Section 6.5, Appendix I.
pub const TICKET_END_SLOT: u32 = 500;

/// Number of ticket entries per validator. N = 2.
/// Equation 6.29, Appendix I.
pub const TICKET_ATTEMPTS: u8 = 2;

/// Maximum number of items in the authorizations pool. O = 8.
/// Equation 8.1, Appendix I.
pub const AUTH_POOL_MAX: usize = 8;

/// Maximum number of items in the authorizations queue. Q = 80.
/// Equation 8.1, Appendix I.
pub const AUTH_QUEUE_MAX: usize = 80;

/// Recent history size in blocks. H = 8.
/// Equation 7.8, Appendix I.
pub const RECENT_HISTORY_SIZE: usize = 8;

/// JAM Common Era: Unix timestamp of 2025-01-01 12:00:00 UTC.
/// Section 4.4: "1,735,732,800 seconds after the Unix Epoch"
pub const JAM_COMMON_ERA_UNIX: u64 = 1_735_732_800;

/// Minimum balance per storage item. BI = 10.
/// Equation 9.8, Appendix I.
pub const BALANCE_PER_ITEM: Balance = 10;

/// Minimum balance per octet of storage. BL = 1.
/// Equation 9.8, Appendix I.
pub const BALANCE_PER_BYTE: Balance = 1;

/// Minimum base balance per service. BS = 100.
/// Equation 9.8, Appendix I.
pub const BALANCE_BASE_SERVICE: Balance = 100;

/// Gas allocated for Accumulation logic. GA = 10_000_000.
/// Appendix I.
pub const GAS_ACCUMULATE: Gas = 10_000_000;

/// Gas allocated for Is-Authorized logic. GI = 50_000_000.
/// Appendix I.
pub const GAS_IS_AUTHORIZED: Gas = 50_000_000;

/// Gas allocated for Refine logic. GR = 5_000_000_000.
/// Appendix I.
pub const GAS_REFINE: Gas = 5_000_000_000;