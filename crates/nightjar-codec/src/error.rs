// Copyright 2026 Algorealm, Inc.
// This file is part of Nightjar.
// Nightjar is free software: you can redistribute it and/or modify
// it under the terms of Apache 2.0 License as published by the Apache Software Foundation.

//! Codec errror types.

use thiserror::Error;


#[derive(Debug, Clone, PartialEq, Error)]
pub enum CodecError {
    #[error("buffer too short: need {needed} bytes, have {available}")]
    BufferTooShort { needed: usize, available: usize },

    #[error("unexpected end of input at offset {offset}")]
    UnexpectedEof { offset: usize },

    #[error("invalid discriminator byte {byte} at offset {offset}")]
    InvalidDiscriminator { byte: u8, offset: usize },

    #[error("value {value} overflows target type")]
    Overflow { value: u128 },

    #[error("sequence length {len} exceeds maximum {max}")]
    SequenceTooLong { len: usize, max: usize },
}