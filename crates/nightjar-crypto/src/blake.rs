// Copyright 2026 Algorealm, Inc.
// This file is part of Nightjar.
// Nightjar is free software: you can redistribute it and/or modify
// it under the terms of Apache 2.0 License as published by the Apache Software Foundation

//! Blake2b-256 hashing — the H() function.
//!
//! Section 3.8.1:
//! "We assume a function H(m ∈ B) ∈ H denoting the Blake2b 256-bit hash"
//!
//! H denotes the set of 256-bit values equivalent to B32.
//! H0 is the zero hash [0]32.

use blake2::{Blake2b, Digest};
use blake2::digest::consts::U32;
use nightjar_types::primitives::Hash;

/// The zero hash H0 = [0; 32].
/// Section 3.8.1: "H0 is the value equal to [0]32"
pub const H0: Hash = [0u8; 32];

/// Blake2b-256 hash function H(m).
///
/// Section 3.8.1: H(m ∈ B) ∈ H
pub fn hash(data: &[u8]) -> Hash {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(data);
    hasher.finalize().into()
}