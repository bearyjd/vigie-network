#![forbid(unsafe_code)]
//! Root-only conntrack helper. Parses kernel-generated `/proc/net/nf_conntrack` text only, has no
//! network access, and talks to the unprivileged agent solely over a unix stream socket.

pub mod agg;
pub mod cli;
pub mod json;
pub mod parse;
pub mod sock;
