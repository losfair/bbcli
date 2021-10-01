use std::{
  io::{ErrorKind, Write},
  os::unix::prelude::OpenOptionsExt,
  path::{Path, PathBuf},
  str::FromStr,
  time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use ed25519_dalek::Signer;
use rand::RngCore;
use reqwest::{
  header::{HeaderMap, HeaderValue},
  Response, StatusCode, Url,
};
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
  #[structopt(long)]
  secret: Option<PathBuf>,

  /// Path to the session cache. Will be created if missing. Defaults to `~/.rwcli.session`.
  #[structopt(long)]
  session_cache: Option<PathBuf>,

  #[structopt(subcommand)]
  cmd: Cmd,
}

#[derive(Debug, StructOpt)]
enum Cmd {
  /// List apps.
  List,

  /// Get the metadata of an app.
  Get { appid: String },
}

struct App {
  endpoint: Url,
  keypair: ed25519_dalek::Keypair,
  session_ready: bool,
  client: reqwest::Client,
  session_cache_path: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
  pretty_env_logger::init_timed();
  let opt = Opt::from_args();
  let home_dir = dirs::home_dir().expect("cannot get home dir");
  let secret_file = match &opt.secret {
    Some(x) => x.clone(),
    None => home_dir.join(".rwcli.secret"),
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
    session_ready: false,
    client: reqwest::Client::new(),
    session_cache_path: match &opt.session_cache {
      Some(x) => x.clone(),
      None => home_dir.join(".rwcli.session"),
    },
  };
  app.run(&opt.cmd).await?;
  Ok(())
}

#[derive(Serialize, Deserialize)]
struct SessionInfo {
  session_id: String,
  expiry: u64,
}

impl App {
  async fn handle_json_response<T: for<'de> Deserialize<'de>>(&self, res: Response) -> Result<T> {
    let status = res.status();
    if !status.is_success() {
      return Err(ServerError(status, format!("{}", res.text().await?)).into());
    }
    Ok(serde_json::from_slice(&res.bytes().await?)?)
  }
  async fn run(&mut self, cmd: &Cmd) -> Result<()> {
    match cmd {
      Cmd::List => {
        self.ensure_session().await?;
        let mut u = self.endpoint.clone();
        u.set_path("/app/list");
        let res = self.client.get(u).send().await?;
        let res: Vec<String> = self.handle_json_response(res).await?;
        println!("{}", serde_yaml::to_string(&res)?);
      }
      Cmd::Get { appid } => {
        self.ensure_session().await?;
        let mut u = self.endpoint.clone();
        u.set_path("/app/metadata");
        u.query_pairs_mut().clear().append_pair("appid", appid);
        let res = self.client.get(u).send().await?;
        let res: serde_json::Value = self.handle_json_response(res).await?;
        println!("{}", serde_yaml::to_string(&res)?);
      }
    }
    Ok(())
  }

  fn reinit_client_with_session(&mut self, sid: &str) -> Result<()> {
    let mut headers = HeaderMap::new();
    headers.insert("x-rwcp-session-id", HeaderValue::from_str(sid)?);
    self.client = reqwest::Client::builder()
      .default_headers(headers)
      .build()?;
    Ok(())
  }

  async fn ensure_session(&mut self) -> Result<()> {
    #[derive(Serialize)]
    struct SessionGrantRequest {
      request_time: u64,
      token_id: String,
      proof_of_grant_request: String,
    }
    if self.session_ready {
      return Ok(());
    }

    if let Some(s) = read_session_cache(&self.session_cache_path) {
      self.reinit_client_with_session(&s)?;
      self.session_ready = true;
      return Ok(());
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;

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
      if status.as_u16() == 403 {
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
      }
      return Err(ServerError(status, format!("{}", res.text().await?)).into());
    }

    let res: SessionInfo = serde_json::from_slice(&res.bytes().await?)?;
    self.reinit_client_with_session(&res.session_id)?;
    self.session_ready = true;
    write_session_cache(&self.session_cache_path, &res);
    Ok(())
  }
}

fn derive_secret_key_for_server(main_key: &[u8; 32], origin: &str) -> [u8; 32] {
  let mut hasher = Sha512::new();
  hasher.update(main_key);
  hasher.update(origin.as_bytes());
  let out = hasher.finalize();
  <[u8; 32]>::try_from(&out[0..32]).unwrap()
}

fn read_session_cache(path: &Path) -> Option<String> {
  if let Ok(x) = std::fs::read_to_string(path) {
    if let Ok(x) = serde_json::from_str::<SessionInfo>(&x) {
      let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
      if x.expiry > now && x.expiry - now > 300 * 1000 {
        return Some(x.session_id);
      }
    }
  }

  None
}

fn write_session_cache(path: &Path, info: &SessionInfo) {
  if let Ok(x) = serde_json::to_vec(&info) {
    if let Ok(mut f) = std::fs::OpenOptions::new()
      .write(true)
      .create(true)
      .mode(0o600)
      .open(path)
    {
      let _ = f.write_all(&x);
    }
  }
}
