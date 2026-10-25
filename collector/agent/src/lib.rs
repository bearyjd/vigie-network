#![forbid(unsafe_code)]
//! Unprivileged Vigie collector agent: pure logic (parsers, batching, signing), thin I/O in main.

pub mod backoff;
pub mod builder;
pub mod config;
pub mod ctfold;
pub mod ctparse;
pub mod ctsock;
pub mod dhcp_assembler;
pub mod dnsmasq;
pub mod dropin;
pub mod httpdate;
pub mod https;
pub mod ids;
pub mod json;
pub mod leases;
pub mod mac;
pub mod mcast;
pub mod model;
pub mod neigh;
pub mod procstat;
pub mod runtime;
pub mod sender;
pub mod sightings;
pub mod sign;
pub mod spool;
pub mod syncstate;
pub mod tail;
pub mod timegate;
pub mod tls_pin;
pub mod transport;
pub mod urgent;
pub mod window;
pub mod wiring;
