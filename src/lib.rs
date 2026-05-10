//! Official Rust SDK for **buttrbase**.
//!
//! Two surfaces, one crate:
//!
//! - [`client`] — call the buttrbase API from your Rust service
//!   (auth, organizations, billing, webhooks, search, jobs, etc.).
//! - [`verify`] — verify buttrbase-issued JWTs in your own Rust service
//!   (drop-in for any service that federates auth through buttrbase).

pub mod client;
pub mod models;
pub mod verify;
