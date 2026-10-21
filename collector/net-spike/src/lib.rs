#![forbid(unsafe_code)]
//! Multicast socket setup, source filtering and receive-error policy shared by the P1 spike
//! binary and the collector agent.

pub mod filter;
pub mod recv;
pub mod sock;
