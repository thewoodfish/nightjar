// Copyright 2025 Algorealm, Inc.
// This file is part of Nightjar.
// Nightjar is free software: you can redistribute it and/or modify
// it under the terms of Apache 2.0 License as published by the Apache Software Foundation.

//! JAM Block Header types.
//! Section 5 of the Graypaper v0.7.2.
//!
//! H ≡ (HP, HR, HX, HT, HE, HW, HO, HI, HV, HS)
//! Equation 5.1

use parity_scale_codec::{Decode, Encode};
use crate::primitives::{
    BandersnatchPublic, BandersnatchSignature, Ed25519Public,
    Hash, TimeSlot, ValidatorIndex,
};


/// A validator key tuple: (Bandersnatch key, Ed25519 key).
/// Used in the epoch marker. Equation 6.27: (kb, ke) | k ← γ'P
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct ValidatorKeyPair {
    /// Bandersnatch key kb — used for block sealing and VRF.
    pub bandersnatch: BandersnatchPublic,
    /// Ed25519 key ke — used for guarantees, assurances, audits.
    pub ed25519: Ed25519Public,
}


/// The epoch marker HE.
/// Present only on the first block of a new epoch.
///
/// Equation 6.27:
/// HE ≡ (η0, η1, [(kb, ke) | k ← γ'P])  if e' > e
///      ∅                                  otherwise
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct EpochMarker {
    /// Current epoch entropy η0.
    pub entropy: Hash,
    /// Previous epoch entropy η1.
    pub entropy_prev: Hash,
    /// Validator keys for the next epoch (one per validator).
    /// Length must equal V = 1023 in a valid marker.
    pub validator_keys: Vec<ValidatorKeyPair>,
}


/// A Safrole seal-key ticket.
/// Set T in the Graypaper.
///
/// Equation 6.6: T ≡ {y ∈ H, e ∈ NN}
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct Ticket {
    /// Verifiably random ticket identifier y (VRF output hash).
    pub id: Hash,
    /// Ticket attempt index e. Must be < N = 2.
    pub attempt: u8,
}


/// The JAM block header.
///
/// Equation 5.1:
/// H ≡ (HP, HR, HX, HT, HE, HW, HO, HI, HV, HS)
///
/// Fields are ordered as they appear in the Graypaper and as they
/// must be serialized for hashing (EU excludes HS, E includes it).
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct Header {
    /// HP — Parent block header hash.
    ///
    /// Equation 5.2: HP ≡ H(E(P(H)))
    /// The Blake2b-256 hash of the SCALE-encoded parent header.
    pub parent_hash: Hash,

    /// HR — Prior state root.
    ///
    /// Equation 5.8: HR ≡ Mσ(σ)
    /// The Merkle root of the state BEFORE this block is applied.
    /// Note: JAM stores the PRIOR state root in the header,
    /// unlike Ethereum which stores the posterior state root.
    pub prior_state_root: Hash,

    /// HX — Extrinsic hash.
    ///
    /// Equation 5.4: HX ≡ H(E(H#(a)))
    /// A Merkle commitment to the block's extrinsic data.
    pub extrinsic_hash: Hash,

    /// HT — Time-slot index.
    ///
    /// Equation 5.7: HT ∈ NT, P(H)T < HT ∧ HT · P ≤ T
    /// Number of 6-second slots since the JAM Common Era.
    pub time_slot: TimeSlot,

    /// HE — Epoch marker (optional).
    ///
    /// Equation 6.27: present iff this is the first block of a new epoch.
    /// Contains randomness and validator keys for the upcoming epoch.
    pub epoch_marker: Option<EpochMarker>,

    /// HW — Winning tickets marker (optional).
    ///
    /// Equation 6.28: present on the first block after ticket submission
    /// closes (slot Y = 500 within the epoch), if the accumulator is full.
    /// Contains the E = 600 ordered ticket identifiers for the next epoch.
    pub winning_tickets: Option<Vec<Ticket>>,

    /// HO — Offenders mark.
    ///
    /// Equation 10.20: sequence of Ed25519 keys of newly misbehaving
    /// validators to be added to ψO (the punish set).
    pub offenders_mark: Vec<Ed25519Public>,

    /// HI — Block author index.
    ///
    /// Equation 5.9: HI ∈ NV
    /// Index into the posterior current validator set κ'.
    /// Valid range: 0..=1022 (V = 1023).
    pub author_index: ValidatorIndex,

    /// HV — Entropy-yielding VRF signature (Bandersnatch).
    ///
    /// Equation 6.17: HV ∈ ∽V^[]_{HA}⟨XE ⌢ Y(HS)⟩
    /// Contributes unbiasable randomness to the entropy pool η.
    /// Context string XE = "$jam_entropy"
    pub entropy_source: BandersnatchSignature,

    /// HS — Block seal (Bandersnatch signature).
    ///
    /// Equations 6.15/6.16: signs EU(H) — the header without this field.
    /// This is always the LAST field. The unsigned header EU(H) is
    /// everything above. Serialization without this field uses EU.
    pub seal: BandersnatchSignature,
}

impl Header {
    /// Compute the hash of this header — H(E(H)).
    /// Used to form the parent_hash of child blocks.
    ///
    /// Equation 5.2: HP ≡ H(E(P(H)))
    /// Requires the codec and crypto crates — implemented there.
    /// This stub returns a placeholder until wired up.
    pub fn hash(&self) -> Hash {
        // TODO: wire in nightjar-codec + nightjar-crypto
        // return blake2b_256(&scale_encode(self))
        [0u8; 32]
    }
}