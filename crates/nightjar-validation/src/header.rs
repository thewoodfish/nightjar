// Copyright 2026 Algorealm, Inc.
// This file is part of Nightjar.
// Nightjar is free software: you can redistribute it and/or modify
// it under the terms of Apache 2.0 License as published by the Apache Software Foundation

//! Validation logic for JAM block headers.
//! Section 5 of the Graypaper v0.7.2.

use nightjar_types::{
    header::Header,
    primitives::{
        JAM_COMMON_ERA_UNIX, SLOT_PERIOD, VALIDATOR_COUNT,
        EPOCH_LENGTH, TICKET_END_SLOT,
    },
};
use crate::error::HeaderError;

/// Everything needed to validate a header beyond the header itself.
pub struct HeaderContext {
    /// The timeslot of the parent block.
    pub parent_slot: u32,

    /// Current wall-clock Unix timestamp in seconds.
    pub current_unix_time: u64,
}

impl HeaderContext {
    pub fn new(parent_slot: u32, current_unix_time: u64) -> Self {
        Self { parent_slot, current_unix_time }
    }

    /// Convert a Unix timestamp to a JAM slot index.
    /// Returns None if the timestamp predates the JAM Common Era.
    pub fn unix_to_slot(unix: u64) -> Option<u32> {
        let elapsed = unix.checked_sub(JAM_COMMON_ERA_UNIX)?;
        Some((elapsed / SLOT_PERIOD) as u32)
    }
}