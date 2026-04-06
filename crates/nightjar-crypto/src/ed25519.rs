// Copyright 2026 Algorealm, Inc.
// This file is part of Nightjar.
// Nightjar is free software: you can redistribute it and/or modify
// it under the terms of Apache 2.0 License as published by the Apache Software Foundation

//! Ed5519 signature verification and signing logic for nightjar.

use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use nightjar_types::primitives::{Ed25519Public, Ed25519Signature};
use crate::error::CryptoError;

/// Verify an Ed25519 signature.
///
/// Section 3.8.2: checks s ∈ V̄_k⟨m⟩
///
/// Returns Ok(()) if the signature is valid for the given
/// public key and message, Err(CryptoError::InvalidSignature) otherwise.
///
/// # Arguments
/// - `public_key`: 32-byte Ed25519 public key k ∈ H̄
/// - `message`: the signed message m ∈ B
/// - `signature`: 64-byte Ed25519 signature
pub fn verify(
    public_key: &Ed25519Public,
    message: &[u8],
    signature: &Ed25519Signature,
) -> Result<(), CryptoError> {
    let vk = VerifyingKey::from_bytes(public_key)
        .map_err(|_| CryptoError::MalformedPublicKey)?;

    let sig = Signature::from_bytes(signature);

    vk.verify(message, &sig)
        .map_err(|_| CryptoError::InvalidSignature)
}