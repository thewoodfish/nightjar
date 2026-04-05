// Copyright 2026 Algorealm, Inc.
// This file is part of Nightjar.
// Nightjar is free software: you can redistribute it and/or modify
// it under the terms of Apache 2.0 License as published by the Apache Software Foundation

//! Unified error types for all validation in nightjar.

use thiserror::Error;
use nightjar_types::primitives::TimeSlot;

#[derive(Debug, Clone, PartialEq, Error)]
pub enum ValidationError {
    #[error("header validation failed: {0}")]
    Header(#[from] HeaderError),
}

/// All reasons a block header can be invalid.
#[derive(Debug, Clone, PartialEq, Error)]
pub enum HeaderError {
    /// HT not strictly greater than parent's timeslot.
    /// Equation 5.7: P(H)T < HT
    #[error("timeslot {our_slot} must be strictly greater than parent slot {parent_slot}")]
    TimeslotNotStrictlyGreater {
        parent_slot: TimeSlot,
        our_slot: TimeSlot,
    },

    /// HT · P > T — timeslot is in the future.
    /// Equation 5.7: HT · P ≤ T
    #[error("timeslot {slot} is in the future (current unix: {current_unix})")]
    TimeslotInFuture {
        slot: TimeSlot,
        current_unix: u64,
    },

    /// HI ≥ V — author index out of bounds.
    /// Equation 5.9: HI ∈ NV, V = 1023
    #[error("author index {index} out of bounds (max: {max})")]
    AuthorIndexOutOfBounds {
        index: u16,
        max: u32,
    },

    /// Parent hash not found in our known chain.
    /// Equation 5.2.
    #[error("parent hash not found in known chain")]
    UnknownParent,
}