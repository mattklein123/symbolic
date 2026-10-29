//! Portable exact-address symbol and runtime-metadata caches, independent of crash SymCache semantics.
//!
//! The validated reader borrows immutable bytes (including memory-mapped files). Exact lookup
//! preserves every alias without interpreting it as a type or an instruction range. Transport
//! compression, authorization, mapping ownership, and display-name policy belong to callers.
//! The optional builder derives rooted ABI descriptions during ingestion; the reader needs only the
//! resulting cache, never the source Mach-O or ingestion-time shared-cache address context.

#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

mod format;
mod reader;
mod types;

#[cfg(feature = "builder")]
mod builder;
#[cfg(feature = "builder")]
mod metadata;
#[cfg(feature = "builder")]
mod writer;

#[cfg(feature = "builder")]
pub use builder::{BuildError, DataCacheBuilder};
#[cfg(feature = "builder")]
pub use metadata::AddressSpace;
pub use reader::{DataCache, DataSection, DataSymbol, Matches};
pub use types::*;

#[cfg(test)]
#[path = "lib_test.rs"]
mod tests;

#[cfg(test)]
#[path = "reader_test.rs"]
mod reader_tests;

#[cfg(all(test, feature = "builder"))]
#[path = "builder_test.rs"]
mod builder_tests;
