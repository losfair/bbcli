use std::{
  io::{ErrorKind, Write},
  os::unix::prelude::OpenOptionsExt,
  path::PathBuf,
  str::FromStr,
  time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use ed25519_dalek::Signer;
use rand::RngCore;
use reqwest::{StatusCode, Url};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use structopt::StructOpt;
use thiserror::Error;

#[derive(Error, Debug)]
#[error("server error: {0} {1}")]
struct ServerError(StatusCode, String);

#[derive(Debug, StructOpt)]
#[structopt(name = "rwcli", about = "CLI for the RW platform")]
struct Opt {
  /// RWCP service endpoint.
  #[structopt(long, default_value = "https://rwcp.app.invariant.cn")]
  endpoint: String,

  /// Path to the secret key. Will be created if missing. Defaults to `~/.rwcli.secret`.
  secret: Option<PathBuf>,

  #[structopt(subcommand)]
  cmd: Cmd,
}

#[derive(Debug, StructOpt)]
enum Cmd {
  /// List apps.
  List,

  /// Get the metadata of an app.
  Get,
}

struct App {
  endpoint: Url,
  keypair: ed25519_dalek::Keypair,
  session_id: Option<(String, u64)>,
  client: reqwest::Client,
}

#[tokio::main]
async fn main() -> Result<()> {
  pretty_env_logger::init_timed();
  let opt = Opt::from_args();
  let secret_file = match &opt.secret {
    Some(x) => x.clone(),
    None => dirs::home_dir()
      .expect("cannot get home dir")
      .join(".rwcli.secret"),
  };
  let secret = match std::fs::read_to_string(&secret_file) {
    Ok(x) => {
      let decoded = base64::decode(&x)?;
      <[u8; 32]>::try_from(&decoded[..])?
    }
    Err(e) if matches!(e.kind(), ErrorKind::NotFound) => {
      let mut s = [0u8; 32];
      rand::thread_rng().fill_bytes(&mut s);
      std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&secret_file)?
        .write_all(base64::encode(&s).as_bytes())?;
      s
    }
    Err(e) => return Err(e.into()),
  };
  let endpoint = Url::from_str(&opt.endpoint)?;
  let origin = endpoint.origin().ascii_serialization();
  log::debug!("origin is {}", origin);
  let secret = derive_secret_key_for_server(&secret, &origin);
  let secret = ed25519_dalek::SecretKey::from_bytes(&secret).unwrap();
  let public = ed25519_dalek::PublicKey::from(&secret);
  let mut app = App {
    keypair: ed25519_dalek::Keypair { secret, public },
    endpoint,
    session_id: None,
    client: reqwest::Client::new(),
  };
  app.run(&opt.cmd).await?;
  Ok(())
}

#[derive(Deserialize)]
struct SessionEntryOutput {
  session_id: String,
  expiry: u64,
}

impl App {
  async fn run(&mut self, _cmd: &Cmd) -> Result<()> {
    let session_id = self.ensure_session().await?;
    println!("session id {}", session_id);
    Ok(())
  }

  async fn ensure_session(&mut self) -> Result<String> {
    #[derive(Serialize)]
    struct SessionGrantRequest {
      request_time: u64,
      token_id: String,
      proof_of_grant_request: String,
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
    if let Some((x, expiry)) = self.session_id.clone() {
      if expiry > now {
        return Ok(x);
      }
    }

    let sig: [u8; 64] = self
      .keypair
      .sign(format!("grant_session:{}", now).as_bytes())
      .to_bytes();
    let mut u = self.endpoint.clone();
    u.set_path("/mksession");
    let req = self
      .client
      .post(u)
      .body(serde_json::to_string(&SessionGrantRequest {
        request_time: now,
        token_id: hex::encode(self.keypair.public.as_bytes()),
        proof_of_grant_request: base64::encode_config(&sig, base64::URL_SAFE_NO_PAD),
      })?)
      .build()?;
    let res = self.client.execute(req).await?;
    let status = res.status();
    if !status.is_success() {
      let mut u = self.endpoint.clone();
      u.set_path("/ghlogin");

      let token_id = hex::encode(self.keypair.public.as_bytes());
      let sig = base64::encode_config(
        &self.keypair.sign(b"init:").to_bytes(),
        base64::URL_SAFE_NO_PAD,
      );
      u.query_pairs_mut()
        .clear()
        .append_pair("token_id", &token_id)
        .append_pair("proof", &sig);
      log::error!("Please authenticate this machine first: {}", u);
      return Err(ServerError(status, format!("{}", res.text().await?)).into());
    }

    let res: SessionEntryOutput = serde_json::from_slice(&res.bytes().await?)?;
    self.session_id = Some((res.session_id.clone(), res.expiry));

    Ok(res.session_id)
  }
}

fn derive_secret_key_for_server(main_key: &[u8; 32], origin: &str) -> [u8; 32] {
  let mut hasher = Sha512::new();
  hasher.update(main_key);
  hasher.update(origin.as_bytes());
  let out = hasher.finalize();
  <[u8; 32]>::try_from(&out[0..32]).unwrap()
}
