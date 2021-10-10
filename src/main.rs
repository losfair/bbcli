mod metadata;

use std::{
  collections::HashMap,
  io::{ErrorKind, Write},
  os::unix::prelude::OpenOptionsExt,
  path::{Path, PathBuf},
  process::Command,
  str::FromStr,
  time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use ed25519_dalek::Signer;
use metadata::{ApnsMetadata, MysqlMetadata};
use rand::RngCore;
use reqwest::{
  header::{HeaderMap, HeaderValue},
  Response, StatusCode, Url,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::convert::TryFrom;
use structopt::StructOpt;
use tempdir::TempDir;
use thiserror::Error;

use crate::metadata::Metadata;

#[derive(Error, Debug)]
#[error("server error: {0} {1}")]
struct ServerError(StatusCode, String);

#[derive(Debug, StructOpt)]
#[structopt(name = "bbcli", about = "CLI for the blueboat platform")]
struct Opt {
  /// BBCP service endpoint.
  #[structopt(long)]
  endpoint: Option<String>,

  #[structopt(subcommand)]
  cmd: Cmd,
}

#[derive(Debug, StructOpt)]
enum Cmd {
  /// List apps.
  List,

  /// Get the metadata of an app.
  Get { appid: String },

  /// Revoke all tokens for this user.
  Revoke,

  /// Show logs.
  Logs {
    appid: String,

    #[structopt(long)]
    reqid: Option<String>,

    #[structopt(long)]
    before: Option<u64>,

    #[structopt(long, default_value = "0")]
    limit: u32,

    #[structopt(long, default_value = "yaml")]
    format: LogFormat,
  },

  /// Deploy a project.
  Deploy {
    /// Path to the spec file.
    #[structopt(long, default_value = "./bbspec.yaml")]
    spec: PathBuf,

    /// Path to the vars file, if any.
    #[structopt(long)]
    vars: Option<PathBuf>,
  },
}

#[derive(Copy, Clone, Debug)]
enum LogFormat {
  Json,
  Yaml,
}

impl FromStr for LogFormat {
  type Err = &'static str;
  fn from_str(x: &str) -> Result<Self, Self::Err> {
    match x {
      "json" => Ok(Self::Json),
      "yaml" => Ok(Self::Yaml),
      _ => Err("invalid log format"),
    }
  }
}

struct App {
  endpoint: Option<Url>,
  session_ready: bool,
  main_secret: [u8; 32],
  client: reqwest::Client,
  session_dir: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
  if std::env::var("RUST_LOG").is_err() {
    std::env::set_var("RUST_LOG", "info");
  }

  pretty_env_logger::init_timed();
  let opt = Opt::from_args();
  let home_dir = dirs::home_dir().expect("cannot get home dir");
  let base_dir = home_dir.join(".bbcli");
  std::fs::create_dir_all(&base_dir)?;

  let secret_file = base_dir.join("secret");

  let session_dir = base_dir.join("sessions");
  std::fs::create_dir_all(&session_dir)?;
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
  let endpoint = if let Some(endpoint) = &opt.endpoint {
    Some(Url::from_str(endpoint)?)
  } else {
    None
  };
  let mut app = App {
    main_secret: secret,
    endpoint,
    session_ready: false,
    client: reqwest::Client::new(),
    session_dir,
  };
  app.run(&opt.cmd).await?;
  Ok(())
}

#[derive(Serialize, Deserialize)]
struct SessionInfo {
  session_id: String,
  expiry: u64,
}

#[derive(Deserialize)]
struct DeploySpec {
  appid: String,
  build: Option<String>,
  artifact: String,

  #[serde(default)]
  env: Vec<String>,
  #[serde(default)]
  mysql: Vec<String>,
  #[serde(default)]
  apns: Vec<String>,

  #[serde(rename = "static")]
  _static: Option<String>,
}

#[derive(Deserialize, Default)]
struct DeployVars {
  endpoint: Option<String>,

  /// If set, the deployed appid will look like `original_appid@instance_id`.
  instance_id: Option<String>,

  #[serde(default)]
  env: HashMap<String, String>,

  #[serde(default)]
  mysql: HashMap<String, MysqlMetadata>,

  #[serde(default)]
  apns: HashMap<String, ApnsMetadata>,
}

impl App {
  fn endpoint(&self) -> Result<Url> {
    #[derive(Error, Debug)]
    #[error("endpoint not set")]
    struct EndpointNotSet;

    Ok(self.endpoint.clone().ok_or(EndpointNotSet)?)
  }
  async fn handle_json_response<T: for<'de> Deserialize<'de>>(
    &mut self,
    res: Response,
  ) -> Result<T> {
    let status = res.status();
    if !status.is_success() {
      if status.as_u16() == 401 {
        log::warn!("Credentials not valid. Clearing cache.");
        let _ = std::fs::remove_file(&self.get_session_cache_file_path()?);
        self.session_ready = false;
      }
      return Err(ServerError(status, format!("{}", res.text().await?)).into());
    }
    Ok(serde_json::from_slice(&res.bytes().await?)?)
  }
  async fn run(&mut self, cmd: &Cmd) -> Result<()> {
    match cmd {
      Cmd::List => {
        self.ensure_session().await?;
        let mut u = self.endpoint()?;
        u.set_path("/app/list");
        let res = self.client.get(u).send().await?;
        let res: Vec<String> = self.handle_json_response(res).await?;
        println!("{}", serde_yaml::to_string(&res)?);
      }
      Cmd::Get { appid } => {
        self.ensure_session().await?;
        let mut u = self.endpoint()?;
        u.set_path("/app/metadata");
        u.query_pairs_mut().clear().append_pair("appid", appid);
        let res = self.client.get(u).send().await?;
        let res: serde_json::Value = self.handle_json_response(res).await?;
        println!("{}", serde_yaml::to_string(&res)?);
      }
      Cmd::Revoke => {
        self.ensure_session().await?;
        let mut u = self.endpoint()?;
        u.set_path("/revoke_token_by_ghid");
        let res = self.client.post(u).send().await?;
        let res: serde_json::Value = self.handle_json_response(res).await?;
        println!("{}", serde_yaml::to_string(&res)?);
      }
      Cmd::Logs {
        appid,
        reqid,
        before,
        limit,
        format,
      } => {
        self
          .run_logs(appid, reqid, *before, *limit, *format)
          .await?;
      }
      Cmd::Deploy { spec, vars } => {
        self.run_deploy(spec, vars).await?;
      }
    }
    Ok(())
  }

  async fn run_logs(
    &mut self,
    appid: &str,
    reqid: &Option<String>,
    before: Option<u64>,
    limit: u32,
    format: LogFormat,
  ) -> Result<()> {
    #[derive(Serialize)]
    struct LogQueryRequest<'a> {
      appid: &'a str,
      reqid: Option<&'a str>,
      before: Option<u64>,
      limit: u32,
    }

    let req = LogQueryRequest {
      appid,
      reqid: reqid.as_ref().map(|x| x.as_str()),
      before,
      limit,
    };

    self.ensure_session().await?;

    let mut u = self.endpoint()?;
    u.set_path("/ops/logs");
    let res = self
      .client
      .post(u)
      .body(serde_json::to_string(&req)?)
      .send()
      .await?;
    let res: serde_json::Value = self.handle_json_response(res).await?;
    match format {
      LogFormat::Json => println!("{}", serde_json::to_string_pretty(&res)?),
      LogFormat::Yaml => println!("{}", serde_yaml::to_string(&res)?),
    }
    Ok(())
  }

  fn set_endpoint_if_missing(&mut self, new_endpoint: &str) -> Result<()> {
    if self.endpoint.is_none() {
      self.endpoint = Some(Url::from_str(new_endpoint)?);
      self.session_ready = false;
    }
    Ok(())
  }

  async fn run_deploy(&mut self, spec_file: &PathBuf, vars_file: &Option<PathBuf>) -> Result<()> {
    #[derive(Error, Debug)]
    #[error("build failed: return code {0}")]
    struct BuildFailed(i32);

    #[derive(Error, Debug)]
    #[error("copy static failed: return code {0}")]
    struct CopyStaticFailed(i32);

    #[derive(Error, Debug)]
    #[error("missing env in vars: {0}")]
    struct MissingEnvInVars(String);

    #[derive(Error, Debug)]
    #[error("missing mysql in vars: {0}")]
    struct MissingMysqlInVars(String);

    #[derive(Error, Debug)]
    #[error("missing apns in vars: {0}")]
    struct MissingApnsInVars(String);

    #[derive(Error, Debug)]
    #[error("s3 put error: {0:?} {1}")]
    struct S3PutError(StatusCode, String);

    #[derive(Error, Debug)]
    #[error("error reading spec file: {0}")]
    struct ErrorReadingSpec(std::io::Error);

    #[derive(Error, Debug)]
    #[error("error reading vars file: {0}")]
    struct ErrorReadingVars(std::io::Error);

    #[derive(Serialize)]
    struct AppUploadRequest {
      appid: String,
      content_length: u64,
    }

    #[derive(Serialize)]
    struct AppCreateRequest<'a> {
      appid: &'a str,
      metadata: &'a Metadata,
    }

    #[derive(Deserialize)]
    struct AppUploadPermit {
      url: String,
      image_id: String,
    }

    #[derive(Deserialize)]
    struct AppCreateResponse {
      metadata_key: String,
    }

    let spec: DeploySpec =
      serde_yaml::from_str(&std::fs::read_to_string(spec_file).map_err(ErrorReadingSpec)?)?;
    let vars: DeployVars = if let Some(vars_file) = vars_file {
      serde_yaml::from_str(&std::fs::read_to_string(vars_file).map_err(ErrorReadingVars)?)?
    } else {
      DeployVars::default()
    };

    // Enter the spec's directory after reading vars file
    let spec_dir = spec_file.parent().expect("cannot get parent of spec file");
    std::env::set_current_dir(spec_dir)?;

    for env in &spec.env {
      if !vars.env.contains_key(env) {
        return Err(MissingEnvInVars(env.clone()).into());
      }
    }
    for mysql in &spec.mysql {
      if !vars.mysql.contains_key(mysql) {
        return Err(MissingMysqlInVars(mysql.clone()).into());
      }
    }
    for apns in &spec.apns {
      if !vars.apns.contains_key(apns) {
        return Err(MissingApnsInVars(apns.clone()).into());
      }
    }

    if let Some(endpoint) = &vars.endpoint {
      self.set_endpoint_if_missing(endpoint)?;
    }

    let td = TempDir::new("bbcli-deploy")?;
    if let Some(d) = &spec._static {
      let status = {
        #[cfg(target_os = "macos")]
        {
          let mut d = PathBuf::from_str(d)?.canonicalize()?;
          d.push("");
          Command::new("cp")
            .args([Path::new("-r"), &d, td.path()])
            .status()?
        }
        #[cfg(not(target_os = "macos"))]
        {
          let d = PathBuf::from_str(d)?.canonicalize()?;
          Command::new("cp")
            .args([Path::new("-rT"), &d, td.path()])
            .status()?
        }
      };
      if !status.success() {
        return Err(CopyStaticFailed(status.code().unwrap_or(1)).into());
      }
    }

    if let Some(build) = &spec.build {
      let status = Command::new("sh").args(["-c", build.as_str()]).status()?;
      if !status.success() {
        return Err(BuildFailed(status.code().unwrap_or(1)).into());
      }
    }

    let mut artifact_target_path = td.path().to_path_buf();
    artifact_target_path.push("index.js");
    std::fs::copy(&spec.artifact, &artifact_target_path)?;

    let mut tar_builder = tar::Builder::new(Vec::new());
    tar_builder.append_dir_all(".", td.path())?;
    let image = tar_builder.into_inner()?;
    log::info!("Image size is {} bytes.", image.len());

    self.ensure_session().await?;

    let upload_request = AppUploadRequest {
      appid: if let Some(instance_id) = &vars.instance_id {
        format!("{}@{}", spec.appid, instance_id)
      } else {
        spec.appid.clone()
      },
      content_length: image.len() as u64,
    };
    let mut u = self.endpoint()?;
    u.set_path("/app/upload");
    let res = self
      .client
      .post(u)
      .body(serde_json::to_string(&upload_request)?)
      .send()
      .await?;
    let permit: AppUploadPermit = self.handle_json_response(res).await?;
    log::debug!(
      "Uploading to {:?} with image id {:?}.",
      permit.url,
      permit.image_id
    );

    let put_url = Url::from_str(&permit.url)?;

    let s3_client = reqwest::Client::new();
    let res = s3_client
      .put(put_url.clone())
      .header("content-type", "application/x-tar")
      .body(image)
      .send()
      .await?;
    let status = res.status();
    if !status.is_success() {
      return Err(S3PutError(status, res.text().await?).into());
    }

    let md = Metadata {
      version: permit.image_id.clone(),
      package: permit.image_id.clone(),
      env: vars.env,
      mysql: vars.mysql,
      apns: vars.apns,
    };
    let create_request = AppCreateRequest {
      appid: &upload_request.appid,
      metadata: &md,
    };
    let mut u = self.endpoint()?;
    u.set_path("/app/create");
    let res = self
      .client
      .post(u)
      .body(serde_json::to_string(&create_request)?)
      .send()
      .await?;
    let res: AppCreateResponse = self.handle_json_response(res).await?;
    println!("App deployed as {}.", upload_request.appid,);
    println!("Endpoint: {}", self.endpoint()?);
    println!("Key: {}", res.metadata_key);

    Ok(())
  }

  fn reinit_client_with_session(&mut self, sid: &str) -> Result<()> {
    let mut headers = HeaderMap::new();
    headers.insert("x-bbcp-session-id", HeaderValue::from_str(sid)?);
    self.client = reqwest::Client::builder()
      .default_headers(headers)
      .build()?;
    Ok(())
  }

  fn origin_repr(&self) -> Result<String> {
    Ok(self.endpoint()?.origin().ascii_serialization())
  }

  fn derive_keypair(&self) -> Result<ed25519_dalek::Keypair> {
    let secret = derive_secret_key_for_server(&self.main_secret, &self.origin_repr()?);
    let secret = ed25519_dalek::SecretKey::from_bytes(&secret).unwrap();
    let public = ed25519_dalek::PublicKey::from(&secret);
    Ok(ed25519_dalek::Keypair { secret, public })
  }

  fn get_session_cache_file_path(&self) -> Result<PathBuf> {
    let session_cache_key = derive_session_cache_key(&self.origin_repr()?);
    Ok(self.session_dir.join(&session_cache_key))
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

    let session_cache_file = self.get_session_cache_file_path()?;

    if let Some(s) = read_session_cache(&session_cache_file) {
      self.reinit_client_with_session(&s)?;
      self.session_ready = true;
      return Ok(());
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;

    let keypair = self.derive_keypair()?;
    let sig: [u8; 64] = keypair
      .sign(format!("grant_session:{}", now).as_bytes())
      .to_bytes();
    let mut u = self.endpoint()?;
    u.set_path("/mksession");
    let req = self
      .client
      .post(u)
      .body(serde_json::to_string(&SessionGrantRequest {
        request_time: now,
        token_id: hex::encode(keypair.public.as_bytes()),
        proof_of_grant_request: base64::encode_config(&sig, base64::URL_SAFE_NO_PAD),
      })?)
      .build()?;
    let res = self.client.execute(req).await?;
    let status = res.status();
    if !status.is_success() {
      if status.as_u16() == 401 {
        let mut u = self.endpoint()?;
        u.set_path("/ghlogin");

        let token_id = hex::encode(keypair.public.as_bytes());
        let sig = base64::encode_config(
          &keypair.sign(format!("init:{}", now).as_bytes()).to_bytes(),
          base64::URL_SAFE_NO_PAD,
        );
        u.query_pairs_mut()
          .clear()
          .append_pair("token_id", &token_id)
          .append_pair("proof", &sig)
          .append_pair("t", &format!("{}", now));
        log::error!("Please authenticate this machine first: {}", u);
      }
      return Err(ServerError(status, format!("{}", res.text().await?)).into());
    }

    let res: SessionInfo = serde_json::from_slice(&res.bytes().await?)?;
    self.reinit_client_with_session(&res.session_id)?;
    self.session_ready = true;
    write_session_cache(&session_cache_file, &res);
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

fn derive_session_cache_key(origin: &str) -> String {
  let mut hasher = Sha512::new();
  hasher.update(origin.as_bytes());
  let out = hasher.finalize();
  hex::encode(&out[..32])
}
