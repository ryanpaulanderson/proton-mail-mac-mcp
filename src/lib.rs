#![forbid(unsafe_code)]

pub mod adapters;
pub mod application;
pub mod cli;
pub mod domain;
pub mod mcp;

pub use domain::error::{AppError, ErrorCode};
