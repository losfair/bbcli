use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Clone)]
pub struct Metadata {
  pub version: String,
  pub package: String,
  pub env: HashMap<String, String>,

  #[serde(default)]
  pub mysql: HashMap<String, MysqlMetadata>,

  #[serde(default)]
  pub apns: HashMap<String, ApnsMetadata>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct MysqlMetadata {
  pub url: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ApnsMetadata {
  pub endpoint: ApnsEndpointMetadata,
  pub cert: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub enum ApnsEndpointMetadata {
  #[serde(rename = "production")]
  Production,

  #[serde(rename = "sandbox")]
  Sandbox,
}
