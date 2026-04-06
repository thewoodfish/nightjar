// Copyright 2026 Algorealm, Inc.
// This file is part of Nightjar.
// Nightjar is free software: you can redistribute it and/or modify
// it under the terms of Apache 2.0 License as published by the Apache Software Foundation

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Error)]
pub enum CryptoError {
    /// Signature verification failed.
    #[error("signature verification failed")]
    InvalidSignature,

    /// Public key is malformed.
    #[error("malformed public key")]
    MalformedPublicKey
}