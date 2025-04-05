#![allow(unused)]

pub const CLIENT: &[u8] = include_bytes!("issuer.json");
pub const ISSUER: &[u8] = include_bytes!("issuer.json");
pub const SERVER: &[u8] = include_bytes!("server.json");
pub const NORMAL_USER: &[u8] = include_bytes!("normal-user.json");
pub const PENDING_USER: &[u8] = include_bytes!("pending-user.json");
