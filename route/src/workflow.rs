use alloy::primitives::{B256, Signature};
use k256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha3::Digest;

use crate::protocol::{self, ExchangeAction, Network, SignSubmit};
use petal::{Ctx, DispatchResponse};

const MAX_BODY: usize = 2 * 1024 * 1024;

struct PrivateKeySigner {
    key: SigningKey,
    address: alloy::primitives::Address,
}
impl PrivateKeySigner {
    fn from_bytes(raw: &[u8]) -> Result<Self, String> {
        if raw.len() != 32 {
            return Err("private key must be 32 bytes".into());
        }
        let key = SigningKey::from_slice(raw).map_err(|e| e.to_string())?;
        let public = key.verifying_key().to_encoded_point(false);
        let digest = sha3::Keccak256::digest(&public.as_bytes()[1..]);
        Ok(Self {
            key,
            address: alloy::primitives::Address::from_slice(&digest[12..]),
        })
    }
    fn address(&self) -> alloy::primitives::Address {
        self.address
    }
    fn sign_hash_sync(&self, hash: &B256) -> Result<Signature, String> {
        let (sig, recovery) = self
            .key
            .sign_prehash_recoverable(hash.as_slice())
            .map_err(|e| e.to_string())?;
        let mut raw = [0u8; 65];
        raw[..64].copy_from_slice(&sig.to_bytes());
        raw[64] = recovery.to_byte();
        Signature::from_raw(&raw).map_err(|e| e.to_string())
    }
}

fn ok_write() -> DispatchResponse {
    DispatchResponse::Write
}
fn invalid(e: impl Into<String>) -> DispatchResponse {
    petal::error(-3, e)
}
fn denied(e: impl Into<String>) -> DispatchResponse {
    petal::error(-2, e)
}
fn backend(e: impl Into<String>) -> DispatchResponse {
    petal::error(-4, e)
}
fn p<'a>(ctx: &'a Ctx, name: &str) -> Result<&'a str, DispatchResponse> {
    petal::param(ctx, name)
}
fn network(ctx: &Ctx) -> Result<Network, DispatchResponse> {
    Network::parse(p(ctx, "network")?).map_err(invalid)
}
fn wallet(ctx: &Ctx) -> Result<String, DispatchResponse> {
    let raw = p(ctx, "wallet")?;
    protocol::parse_address(raw)
        .map(|a| format!("{a:#x}"))
        .map_err(invalid)
}
fn route(ctx: &Ctx) -> &'static str {
    petal::current_route_path(ctx)
}
fn state_key(parts: &[&str]) -> String {
    format!("state/{}", parts.join("/"))
}
fn secret_key(parts: &[&str]) -> String {
    format!("secrets/{}", parts.join("/"))
}
fn save_json(key: String, v: &impl Serialize, secret: bool) -> Result<(), DispatchResponse> {
    let b = serde_json::to_vec(v).map_err(|e| backend(e.to_string()))?;
    petal::sdk::put(&key, &b, secret).map_err(backend)
}
fn save_json_new(key: String, v: &impl Serialize, secret: bool) -> Result<(), DispatchResponse> {
    let b = serde_json::to_vec(v).map_err(|e| backend(e.to_string()))?;
    petal::sdk::put_new(&key, &b, secret).map_err(backend)
}
fn load_json<T: for<'de> Deserialize<'de>>(key: String) -> Result<Option<T>, DispatchResponse> {
    let Some(b) = petal::sdk::get(&key).map_err(backend)? else {
        return Ok(None);
    };
    serde_json::from_slice(&b)
        .map(Some)
        .map_err(|e| backend(format!("stored state is invalid: {e}")))
}
fn http_raw(net: Network, path: &str, body: Value) -> Result<(u16, Vec<u8>), DispatchResponse> {
    let b = serde_json::to_vec(&body).map_err(|e| backend(e.to_string()))?;
    let (status, raw) = petal::sdk::http(
        "POST",
        &format!("{}{path}", net.url()),
        vec![("content-type".into(), "application/json".into())],
        b,
    )
    .map_err(backend)?;
    if raw.len() > MAX_BODY {
        return Err(backend("Hyperliquid response too large"));
    };
    Ok((status, raw))
}
pub fn http_json(net: Network, path: &str, body: Value) -> Result<Value, DispatchResponse> {
    let (status, raw) = http_raw(net, path, body)?;
    let v: Value = serde_json::from_slice(&raw)
        .map_err(|e| backend(format!("Hyperliquid returned invalid JSON: {e}")))?;
    if !(200..300).contains(&status) {
        return Err(backend(format!(
            "Hyperliquid API status {status}: {}",
            safe_json(&v)
        )));
    };
    Ok(v)
}
pub fn http_read_json(net: Network, path: &str, body: Value) -> DispatchResponse {
    let (status, raw) = match http_raw(net, path, body) {
        Ok(response) => response,
        Err(e) => return e,
    };
    read_json_response(status, raw)
}
fn read_json_response(status: u16, raw: Vec<u8>) -> DispatchResponse {
    if let Err(e) = serde_json::from_slice::<serde::de::IgnoredAny>(&raw) {
        return backend(format!("Hyperliquid returned invalid JSON: {e}"));
    }
    if !(200..300).contains(&status) {
        let v: Value = match serde_json::from_slice(&raw) {
            Ok(v) => v,
            Err(e) => return backend(format!("Hyperliquid returned invalid JSON: {e}")),
        };
        return backend(format!(
            "Hyperliquid API status {status}: {}",
            safe_json(&v)
        ));
    }
    DispatchResponse::Read(raw)
}
fn safe_json(v: &Value) -> String {
    let s = serde_json::to_string(v).unwrap_or_else(|_| "<invalid>".into());
    s.chars().take(4096).collect()
}

pub fn exchange_last_response(n: Network, w: &str) -> DispatchResponse {
    let key = state_key(&[
        "exchange",
        if matches!(n, Network::Mainnet) {
            "mainnet"
        } else {
            "testnet"
        },
        w,
        "last_response.json",
    ]);
    match petal::sdk::get(&key) {
        Ok(Some(b)) => DispatchResponse::Read(b),
        Ok(None) => invalid("no exchange response has been recorded"),
        Err(e) => backend(e),
    }
}

pub fn validate_body_size(body: &[u8]) -> Result<(), DispatchResponse> {
    if body.len() > MAX_BODY {
        Err(invalid("request body is too large"))
    } else {
        Ok(())
    }
}

pub fn owner_action_write(
    ctx: &Ctx,
    n: Network,
    w: String,
    operation: &str,
    body: &[u8],
    req: SignSubmit,
) -> DispatchResponse {
    let (nonce, pending_nonce_key, completed) = match owner_nonce(n, &w, operation, body, req.nonce)
    {
        Ok(x) => x,
        Err(e) => return e,
    };
    if completed {
        return ok_write();
    }
    let vault = match req.vault_address.as_deref() {
        Some(x) => match protocol::parse_address(x) {
            Ok(a) => Some(a),
            Err(e) => return invalid(e),
        },
        None => None,
    };
    let hash = match protocol::l1_signing_hash(n, &req.action, nonce, vault, req.expires_after) {
        Ok(h) => h,
        Err(e) => return invalid(e),
    };
    let sig = match petal::sdk::sign(&w, hash.as_slice(), req.action.intent()) {
        Ok(petal::sdk::Sign::Signature(s)) => match protocol::SignatureJson::from_raw(&s) {
            Ok(x) => x,
            Err(e) => return invalid(e),
        },
        Ok(petal::sdk::Sign::Approval {
            action_id,
            ceremony_url,
            expires_ms,
        }) => {
            if let Some(key) = pending_nonce_key
                && let Err(e) = save_json(
                    key,
                    &PendingNonce {
                        nonce,
                        expires_ms,
                        completed: false,
                    },
                    false,
                )
            {
                return e;
            }
            return approval(
                ctx,
                "exchange",
                &json!({"action_id":action_id,"ceremony_url":ceremony_url,"expires_ms":expires_ms}),
            );
        }
        Err(e) => return denied(format!("signing denied: {e}")),
    };
    if let Some(key) = pending_nonce_key.as_ref()
        && let Err(e) = save_json(
            key.clone(),
            &PendingNonce {
                nonce,
                expires_ms: u64::MAX,
                completed: false,
            },
            false,
        )
    {
        return e;
    }
    let response = submit_l1(
        n,
        w,
        req.action,
        nonce,
        sig,
        req.vault_address,
        req.expires_after,
    );
    if matches!(response, DispatchResponse::Write)
        && let Some(key) = pending_nonce_key
        && let Err(e) = save_json(
            key,
            &PendingNonce {
                nonce,
                expires_ms: u64::MAX,
                completed: true,
            },
            false,
        )
    {
        return e;
    }
    response
}

fn owner_nonce_key(n: Network, w: &str, leaf: &str, body: &[u8]) -> String {
    let digest = sha3::Keccak256::digest(body);
    state_key(&[
        "exchange",
        "pending",
        if matches!(n, Network::Mainnet) {
            "mainnet"
        } else {
            "testnet"
        },
        w,
        leaf,
        &hex::encode(digest),
        "nonce.json",
    ])
}

fn owner_nonce(
    n: Network,
    w: &str,
    leaf: &str,
    body: &[u8],
    explicit: Option<u64>,
) -> Result<(u64, Option<String>, bool), DispatchResponse> {
    if let Some(nonce) = explicit {
        return Ok((nonce, None, false));
    }
    let key = owner_nonce_key(n, w, leaf, body);
    let now = petal::sdk::now_ms();
    for _ in 0..4 {
        if let Some(pending) = load_json::<PendingNonce>(key.clone())? {
            if pending.completed {
                return Ok((pending.nonce, Some(key), true));
            }
            if pending.expires_ms <= now {
                return Err(invalid(
                    "approval expired; retry with an explicit fresh nonce",
                ));
            }
            return Ok((pending.nonce, Some(key), false));
        }
        let candidate = PendingNonce {
            nonce: now,
            expires_ms: u64::MAX,
            completed: false,
        };
        if save_json_new(key.clone(), &candidate, false).is_ok() {
            return Ok((candidate.nonce, Some(key), false));
        }
    }
    Err(backend(
        "owner nonce reservation changed concurrently; retry",
    ))
}

#[derive(Debug, Serialize, Deserialize)]
struct PendingNonce {
    nonce: u64,
    expires_ms: u64,
    #[serde(default)]
    completed: bool,
}
fn session_nonce(
    n: Network,
    w: &str,
    id: &str,
    action: &ExchangeAction,
    explicit: Option<u64>,
) -> Result<(u64, Option<String>, bool), DispatchResponse> {
    if let Some(nonce) = explicit {
        return Ok((nonce, None, false));
    }
    let encoded = rmp_serde::to_vec_named(action).map_err(|e| backend(e.to_string()))?;
    let digest = hex::encode(sha3::Keccak256::digest(encoded));
    let key = session_key(n, w, id, &format!("operations/{digest}/nonce.json"));
    if let Some(pending) = load_json::<PendingNonce>(key.clone())? {
        return Ok((pending.nonce, Some(key), pending.completed));
    }
    let candidate = PendingNonce {
        nonce: petal::sdk::now_ms(),
        expires_ms: u64::MAX,
        completed: false,
    };
    match save_json_new(key.clone(), &candidate, false) {
        Ok(()) => Ok((candidate.nonce, Some(key), false)),
        Err(first_error) => match load_json::<PendingNonce>(key.clone())? {
            Some(winner) => Ok((winner.nonce, Some(key), winner.completed)),
            None => Err(first_error),
        },
    }
}

pub fn submit_l1(
    n: Network,
    w: String,
    action: ExchangeAction,
    nonce: u64,
    sig: protocol::SignatureJson,
    vault: Option<String>,
    expires: Option<u64>,
) -> DispatchResponse {
    let payload = match protocol::exchange_payload(action, nonce, sig, vault, expires) {
        Ok(x) => x,
        Err(e) => return invalid(e),
    };
    match http_json(n, "/exchange", payload) {
        Ok(v) => {
            if let Err(e) = protocol::validate_exchange_response(&v) {
                return backend(e);
            }
            let key = state_key(&[
                "exchange",
                if matches!(n, Network::Mainnet) {
                    "mainnet"
                } else {
                    "testnet"
                },
                &w,
                "last_response.json",
            ]);
            if let Err(e) = save_json(key, &v, false) {
                return e;
            }
            ok_write()
        }
        Err(e) => e,
    }
}

#[derive(Debug, Deserialize)]
struct UsdSend {
    destination: String,
    amount: String,
    #[serde(default)]
    nonce: Option<u64>,
}
pub fn usd_send(ctx: &Ctx, n: Network, w: String, body: &[u8]) -> DispatchResponse {
    let req = match serde_json::from_slice::<UsdSend>(body) {
        Ok(x) => x,
        Err(e) => return invalid(format!("invalid send_asset body: {e}")),
    };
    if let Err(e) = protocol::validate_usdc_amount(&req.amount) {
        return invalid(e);
    }
    let dest = match protocol::parse_address(&req.destination) {
        Ok(x) => x,
        Err(e) => return invalid(e),
    };
    let (nonce, pending_nonce_key, completed) =
        match owner_nonce(n, &w, "send_asset.json", body, req.nonce) {
            Ok(x) => x,
            Err(e) => return e,
        };
    if completed {
        return ok_write();
    }
    let (action, hash) = match protocol::usd_send_hash(n, dest, &req.amount, nonce) {
        Ok(x) => x,
        Err(e) => return invalid(e),
    };
    let sig = match petal::sdk::sign(&w, hash.as_slice(), "hyperliquid.usd_send") {
        Ok(petal::sdk::Sign::Signature(s)) => match protocol::SignatureJson::from_raw(&s) {
            Ok(x) => x,
            Err(e) => return invalid(e),
        },
        Ok(petal::sdk::Sign::Approval {
            action_id,
            ceremony_url,
            expires_ms,
        }) => {
            if let Some(key) = pending_nonce_key
                && let Err(e) = save_json(
                    key,
                    &PendingNonce {
                        nonce,
                        expires_ms,
                        completed: false,
                    },
                    false,
                )
            {
                return e;
            }
            return approval(
                ctx,
                "usd_send",
                &json!({"action_id":action_id,"ceremony_url":ceremony_url,"expires_ms":expires_ms}),
            );
        }
        Err(e) => return denied(format!("signing denied: {e}")),
    };
    if let Some(key) = pending_nonce_key.as_ref()
        && let Err(e) = save_json(
            key.clone(),
            &PendingNonce {
                nonce,
                expires_ms: u64::MAX,
                completed: false,
            },
            false,
        )
    {
        return e;
    }
    match http_json(n, "/exchange", protocol::user_payload(action, nonce, sig)) {
        Ok(v) => {
            if let Err(e) = protocol::validate_exchange_response(&v) {
                return backend(e);
            }
            let key = state_key(&[
                "exchange",
                if matches!(n, Network::Mainnet) {
                    "mainnet"
                } else {
                    "testnet"
                },
                &w,
                "last_response.json",
            ]);
            if let Err(e) = save_json(key, &v, false) {
                return e;
            }
            if let Some(key) = pending_nonce_key
                && let Err(e) = save_json(
                    key,
                    &PendingNonce {
                        nonce,
                        expires_ms: u64::MAX,
                        completed: true,
                    },
                    false,
                )
            {
                return e;
            }
            ok_write()
        }
        Err(e) => e,
    }
}
fn approval(ctx: &Ctx, kind: &str, v: &Value) -> DispatchResponse {
    let _ = save_json(state_key(&["approvals", route(ctx)]), v, false);
    denied(format!("approval required for {kind}: {}", safe_json(v)))
}
fn valid_session_id(raw: &str) -> Result<(), String> {
    if raw.is_empty()
        || raw == "."
        || raw == ".."
        || raw.len() > 128
        || !raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        Err("session id contains unsafe characters".into())
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub schema: String,
    pub network: String,
    pub wallet: String,
    pub id: String,
    pub agent_address: String,
    pub agent_name: String,
    pub created_ms: u64,
    pub expires_ms: u64,
    pub max_notional_usd: Option<String>,
    pub max_leverage: Option<u32>,
    pub assets: Vec<String>,
    pub stopped: bool,
    pub last_response: Option<Value>,
    pub last_error: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Pending {
    session: Session,
    key_hex: String,
    nonce: u64,
    #[serde(default)]
    approval_expires_ms: Option<u64>,
    #[serde(default)]
    request_digest: String,
    #[serde(default)]
    completed: bool,
}
#[derive(Debug, Deserialize)]
struct NewSession {
    id: String,
    #[serde(default)]
    duration_ms: Option<u64>,
    #[serde(default)]
    agent_name: Option<String>,
    #[serde(default)]
    max_notional_usd: Option<String>,
    #[serde(default)]
    max_leverage: Option<u32>,
    #[serde(default)]
    assets: Vec<String>,
    #[serde(default)]
    nonce: Option<u64>,
}
fn session_key(n: Network, w: &str, id: &str, file: &str) -> String {
    state_key(&[
        "sessions",
        if matches!(n, Network::Mainnet) {
            "mainnet"
        } else {
            "testnet"
        },
        w,
        id,
        file,
    ])
}
pub fn load_session(n: Network, w: &str, id: &str) -> Result<Option<Session>, DispatchResponse> {
    load_json(session_key(n, w, id, "session.json"))
}

pub fn load_wallet_session_error(n: Network, w: &str) -> Result<Option<String>, DispatchResponse> {
    load_json(state_key(&[
        "sessions",
        if matches!(n, Network::Mainnet) {
            "mainnet"
        } else {
            "testnet"
        },
        w,
        "last_error.json",
    ]))
}

pub fn load_session_response(
    n: Network,
    w: &str,
    id: &str,
) -> Result<Option<Value>, DispatchResponse> {
    load_json(session_key(n, w, id, "last_response.json"))
}

pub fn load_session_error(
    n: Network,
    w: &str,
    id: &str,
) -> Result<Option<String>, DispatchResponse> {
    load_json(session_key(n, w, id, "last_error.json"))
}

fn active_session(n: Network, w: &str, id: &str) -> Result<Session, DispatchResponse> {
    let Some(session) = load_session(n, w, id)? else {
        return Err(petal::error(-1, "session not found"));
    };
    if session.stopped {
        return Err(denied("session is stopped"));
    }
    if session.expires_ms <= petal::sdk::now_ms() {
        return Err(denied("session has expired"));
    }
    Ok(session)
}

pub fn stop_session(n: Network, w: &str, id: &str) -> DispatchResponse {
    let Some(mut session) = (match load_session(n, w, id) {
        Ok(session) => session,
        Err(response) => return response,
    }) else {
        return petal::error(-1, "session not found");
    };
    session.stopped = true;
    session.last_error = None;
    match save_json(session_key(n, w, id, "session.json"), &session, false) {
        Ok(()) => ok_write(),
        Err(response) => response,
    }
}

pub fn cancel_all_session(n: Network, w: &str, id: &str) -> DispatchResponse {
    let mut session = match active_session(n, w, id) {
        Ok(session) => session,
        Err(response) => return response,
    };
    let key = match session_agent_key(w, id, &session) {
        Ok(key) => key,
        Err(response) => return response,
    };
    session_cancel_all(n, w, id, &mut session, &key)
}

pub fn close_all_session(n: Network, w: &str, id: &str) -> DispatchResponse {
    let mut session = match active_session(n, w, id) {
        Ok(session) => session,
        Err(response) => return response,
    };
    let key = match session_agent_key(w, id, &session) {
        Ok(key) => key,
        Err(response) => return response,
    };
    session_close_all(n, w, id, &mut session, &key)
}

pub fn session_action_write(n: Network, w: &str, id: &str, req: SignSubmit) -> DispatchResponse {
    let mut s = match active_session(n, w, id) {
        Ok(session) => session,
        Err(response) => return response,
    };
    if s.stopped {
        return denied("session is stopped");
    };
    if s.expires_ms <= petal::sdk::now_ms() {
        return denied("session has expired");
    };
    if let Err(e) = session_policy(&s, &req.action) {
        return denied(e);
    };
    let key = match petal::sdk::get(&secret_key(&["sessions", &s.network, w, id, "agent_key"])) {
        Ok(Some(x)) => x,
        Ok(None) => {
            return backend("session agent key is missing; recover the session through the owner");
        }
        Err(e) => return backend(e),
    };
    let signer = match PrivateKeySigner::from_bytes(&key) {
        Ok(x) => x,
        Err(e) => return backend(format!("agent key invalid: {e}")),
    };
    let (nonce, operation_key, completed) = match session_nonce(n, w, id, &req.action, req.nonce) {
        Ok(x) => x,
        Err(e) => return e,
    };
    if completed {
        return ok_write();
    }
    let vault = match req.vault_address.as_deref() {
        Some(x) => match protocol::parse_address(x) {
            Ok(a) => Some(a),
            Err(e) => return invalid(e),
        },
        None => None,
    };
    let hash = match protocol::l1_signing_hash(n, &req.action, nonce, vault, req.expires_after) {
        Ok(x) => x,
        Err(e) => return invalid(e),
    };
    let sig = match signer.sign_hash_sync(&hash) {
        Ok(x) => match protocol::SignatureJson::from_raw(&x.as_bytes()) {
            Ok(v) => v,
            Err(e) => return backend(e),
        },
        Err(e) => return backend(format!("agent signing failed: {e}")),
    };
    let action_kind = req.action.kind();
    let payload = match protocol::exchange_payload(
        req.action,
        nonce,
        sig,
        req.vault_address,
        req.expires_after,
    ) {
        Ok(x) => x,
        Err(e) => return invalid(e),
    };
    match http_json(n, "/exchange", payload) {
        Ok(v) => {
            if let Err(e) = protocol::validate_exchange_response(&v) {
                let msg = e.clone();
                s.last_error = Some(msg.clone());
                let _ = save_json(session_key(n, w, id, "session.json"), &s, false);
                let _ = save_json(session_key(n, w, id, "last_error.json"), &msg, false);
                let _ = append_audit(
                    n,
                    w,
                    id,
                    &json!({"time_ms":nonce,"event":"session_action_error","action":action_kind,"error":msg}),
                );
                return backend(e);
            }
            s.last_response = Some(v.clone());
            s.last_error = None;
            if let Err(e) = save_json(session_key(n, w, id, "session.json"), &s, false) {
                return e;
            };
            if let Err(e) = save_json(session_key(n, w, id, "last_response.json"), &v, false) {
                return e;
            };
            let _ = petal::sdk::delete(&session_key(n, w, id, "last_error.json"));
            let _ = append_audit(
                n,
                w,
                id,
                &json!({"time_ms":nonce,"event":"session_action","action":action_kind,"response":v}),
            );
            if let Some(key) = operation_key
                && let Err(e) = save_json(
                    key,
                    &PendingNonce {
                        nonce,
                        expires_ms: u64::MAX,
                        completed: true,
                    },
                    false,
                )
            {
                return e;
            }
            ok_write()
        }
        Err(e) => {
            let msg = format!("{e:?}");
            s.last_error = Some(msg.clone());
            let _ = save_json(session_key(n, w, id, "session.json"), &s, false);
            let _ = save_json(session_key(n, w, id, "last_error.json"), &msg, false);
            let _ = append_audit(
                n,
                w,
                id,
                &json!({"time_ms":nonce,"event":"session_action_error","action":action_kind,"error":msg}),
            );
            e
        }
    }
}
fn session_agent_key(w: &str, id: &str, s: &Session) -> Result<Vec<u8>, DispatchResponse> {
    match petal::sdk::get(&secret_key(&["sessions", &s.network, w, id, "agent_key"])) {
        Ok(Some(x)) => Ok(x),
        Ok(None) => Err(backend(
            "session agent key is missing; recover the session through the owner",
        )),
        Err(e) => Err(backend(e)),
    }
}
fn append_audit(n: Network, w: &str, id: &str, event: &Value) -> Result<(), DispatchResponse> {
    let mut line = serde_json::to_vec(event).map_err(|e| backend(e.to_string()))?;
    line.push(b'\n');
    let time = event
        .get("time_ms")
        .and_then(Value::as_u64)
        .unwrap_or_else(petal::sdk::now_ms);
    let digest = hex::encode(sha3::Keccak256::digest(&line));
    let key = session_key(n, w, id, &format!("audit/{time:020}-{digest}.jsonl"));
    match petal::sdk::put_new(&key, &line, false) {
        Ok(()) => Ok(()),
        Err(e) => match petal::sdk::get(&key) {
            Ok(Some(existing)) if existing == line => Ok(()),
            _ => Err(backend(e)),
        },
    }
}

pub fn read_audit(n: Network, w: &str, id: &str) -> Result<Vec<u8>, String> {
    let mut out = petal::sdk::get(&session_key(n, w, id, "audit.jsonl"))?.unwrap_or_default();
    if out.len() > MAX_BODY {
        out.clear();
    }
    let prefix = session_key(n, w, id, "audit/");
    let mut keys = petal::sdk::list(&prefix)?;
    keys.sort();
    for key in keys.iter().skip(keys.len().saturating_sub(1024)) {
        let Some(line) = petal::sdk::get(key)? else {
            continue;
        };
        if out.len().saturating_add(line.len()) > MAX_BODY {
            break;
        }
        out.extend_from_slice(&line);
    }
    Ok(out)
}
fn session_agent_submit(
    n: Network,
    w: &str,
    id: &str,
    s: &mut Session,
    key: &[u8],
    action: ExchangeAction,
) -> DispatchResponse {
    if let Err(e) = action.validate() {
        return invalid(e);
    }
    if let Err(e) = session_policy(s, &action) {
        return denied(e);
    };
    let signer = match PrivateKeySigner::from_bytes(key) {
        Ok(x) => x,
        Err(e) => return backend(format!("agent key invalid: {e}")),
    };
    let (nonce, operation_key, completed) = match session_nonce(n, w, id, &action, None) {
        Ok(x) => x,
        Err(e) => return e,
    };
    if completed {
        return ok_write();
    }
    let hash = match protocol::l1_signing_hash(n, &action, nonce, None, None) {
        Ok(x) => x,
        Err(e) => return invalid(e),
    };
    let sig = match signer.sign_hash_sync(&hash) {
        Ok(x) => match protocol::SignatureJson::from_raw(&x.as_bytes()) {
            Ok(v) => v,
            Err(e) => return backend(e),
        },
        Err(e) => return backend(format!("agent signing failed: {e}")),
    };
    let payload = match protocol::exchange_payload(action.clone(), nonce, sig, None, None) {
        Ok(x) => x,
        Err(e) => return invalid(e),
    };
    match http_json(n, "/exchange", payload) {
        Ok(v) => {
            if let Err(e) = protocol::validate_exchange_response(&v) {
                let msg = e.clone();
                s.last_error = Some(msg.clone());
                let _ = save_json(session_key(n, w, id, "session.json"), s, false);
                let _ = save_json(session_key(n, w, id, "last_error.json"), &msg, false);
                let _ = append_audit(
                    n,
                    w,
                    id,
                    &json!({"time_ms":nonce,"event":"session_action_error","action":action.kind(),"error":msg}),
                );
                return backend(e);
            }
            s.last_response = Some(v.clone());
            s.last_error = None;
            if let Err(e) = save_json(session_key(n, w, id, "session.json"), s, false) {
                return e;
            };
            if let Err(e) = save_json(session_key(n, w, id, "last_response.json"), &v, false) {
                return e;
            };
            let _ = petal::sdk::delete(&session_key(n, w, id, "last_error.json"));
            let _ = append_audit(
                n,
                w,
                id,
                &json!({"time_ms":nonce,"event":"session_action","action":action.kind(),"response":v}),
            );
            if let Some(key) = operation_key
                && let Err(e) = save_json(
                    key,
                    &PendingNonce {
                        nonce,
                        expires_ms: u64::MAX,
                        completed: true,
                    },
                    false,
                )
            {
                return e;
            }
            ok_write()
        }
        Err(e) => {
            let msg = format!("{e:?}");
            s.last_error = Some(msg.clone());
            let _ = save_json(session_key(n, w, id, "session.json"), s, false);
            let _ = save_json(session_key(n, w, id, "last_error.json"), &msg, false);
            let _ = append_audit(
                n,
                w,
                id,
                &json!({"time_ms":nonce,"event":"session_action_error","action":action.kind(),"error":msg}),
            );
            e
        }
    }
}
fn value_string(v: &Value) -> Option<String> {
    v.as_str()
        .map(str::to_owned)
        .or_else(|| v.as_f64().map(|x| format!("{x}")))
}
#[derive(Clone, Copy)]
struct PerpAsset {
    id: u32,
    sz_decimals: u32,
}
fn asset_metadata(
    n: Network,
) -> Result<std::collections::BTreeMap<String, PerpAsset>, DispatchResponse> {
    let v = http_json(n, "/info", json!({"type":"meta"}))?;
    let mut out = std::collections::BTreeMap::new();
    if let Some(universe) = v.get("universe").and_then(Value::as_array) {
        for (i, item) in universe.iter().enumerate() {
            if let Some(name) = item.get("name").and_then(Value::as_str) {
                let sz_decimals = item
                    .get("szDecimals")
                    .and_then(Value::as_u64)
                    .and_then(|value| u32::try_from(value).ok())
                    .unwrap_or(0);
                out.insert(
                    name.to_owned(),
                    PerpAsset {
                        id: i as u32,
                        sz_decimals,
                    },
                );
            }
        }
    }
    Ok(out)
}
fn asset_ids(n: Network) -> Result<std::collections::BTreeMap<String, u32>, DispatchResponse> {
    asset_metadata(n).map(|assets| {
        assets
            .into_iter()
            .map(|(name, asset)| (name, asset.id))
            .collect()
    })
}
fn session_cancel_all(
    n: Network,
    w: &str,
    id: &str,
    s: &mut Session,
    key: &[u8],
) -> DispatchResponse {
    let open = match http_json(n, "/info", json!({"type":"openOrders","user":w})) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let ids = match asset_ids(n) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut cancels = Vec::new();
    if let Some(items) = open.as_array() {
        for item in items {
            let Some(coin) = item.get("coin").and_then(Value::as_str) else {
                continue;
            };
            let Some(asset) = ids.get(coin) else { continue };
            if !session_allows_asset(s, *asset) {
                continue;
            }
            let Some(oid) = item
                .get("oid")
                .and_then(|v| v.as_u64().or_else(|| v.as_str()?.parse().ok()))
            else {
                continue;
            };
            cancels.push(json!({"a":asset,"o":oid}));
        }
    }
    if cancels.is_empty() {
        return ok_write();
    }
    let action = match serde_json::from_value::<ExchangeAction>(
        json!({"type":"cancel","cancels":cancels}),
    ) {
        Ok(v) => v,
        Err(e) => return invalid(e.to_string()),
    };
    session_agent_submit(n, w, id, s, key, action)
}
fn close_price(raw: &str, buy: bool, sz_decimals: u32) -> Result<String, String> {
    let x: f64 = raw
        .parse()
        .map_err(|_| format!("invalid market price {raw}"))?;
    if !x.is_finite() || x <= 0.0 {
        return Err("market price must be positive".into());
    };
    let y = if buy { x * 1.5 } else { x * 0.5 };
    let significant_precision = 4 - y.log10().floor() as i32;
    let precision = significant_precision.min(6_u32.saturating_sub(sz_decimals) as i32);
    let factor = 10_f64.powi(-precision);
    let scaled = y / factor;
    let rounded = if buy { scaled.ceil() } else { scaled.floor() } * factor;
    let mut out = if precision >= 0 {
        format!("{rounded:.precision$}", precision = precision as usize)
    } else {
        format!("{rounded:.0}")
    };
    while out.contains('.') && out.ends_with('0') {
        out.pop();
    }
    if out.ends_with('.') {
        out.pop();
    }
    Ok(out)
}
fn session_close_all(
    n: Network,
    w: &str,
    id: &str,
    s: &mut Session,
    key: &[u8],
) -> DispatchResponse {
    let state = match http_json(n, "/info", json!({"type":"clearinghouseState","user":w})) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mids = match http_json(n, "/info", json!({"type":"allMids"})) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let assets = match asset_metadata(n) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut orders = Vec::new();
    if let Some(items) = state.get("assetPositions").and_then(Value::as_array) {
        for item in items {
            let pos = item.get("position").unwrap_or(item);
            let Some(coin) = pos.get("coin").and_then(Value::as_str) else {
                continue;
            };
            let Some(asset) = assets.get(coin) else {
                continue;
            };
            if !session_allows_asset(s, asset.id) {
                continue;
            }
            let Some(szi) = pos.get("szi").and_then(value_string) else {
                continue;
            };
            let Ok(size): Result<f64, _> = szi.parse() else {
                continue;
            };
            if !size.is_finite() || size == 0.0 {
                continue;
            };
            let buy = size < 0.0;
            let Some(mid) = mids.get(coin).and_then(value_string) else {
                continue;
            };
            let price = match close_price(&mid, buy, asset.sz_decimals) {
                Ok(v) => v,
                Err(e) => return invalid(e),
            };
            orders.push(protocol::OrderWire {
                asset: asset.id,
                is_buy: buy,
                price,
                size: canonical_abs_decimal(&szi),
                reduce_only: true,
                order_type: protocol::OrderTypeWire {
                    limit: Some(protocol::LimitOrderType {
                        tif: protocol::TimeInForce::Ioc,
                    }),
                    trigger: None,
                },
                cloid: None,
            });
        }
    }
    if orders.is_empty() {
        return ok_write();
    }
    let action = ExchangeAction::Order {
        orders,
        grouping: protocol::Grouping::Na,
        builder: None,
    };
    session_agent_submit(n, w, id, s, key, action)
}
fn canonical_abs_decimal(raw: &str) -> String {
    let mut value = raw.strip_prefix('-').unwrap_or(raw).to_owned();
    while value.contains('.') && value.ends_with('0') {
        value.pop();
    }
    if value.ends_with('.') {
        value.pop();
    }
    value
}
fn session_allows_asset(session: &Session, asset: u32) -> bool {
    session.assets.is_empty() || session.assets.contains(&asset.to_string())
}
fn session_policy(s: &Session, a: &ExchangeAction) -> Result<(), String> {
    a.validate()?;
    if let ExchangeAction::UpdateLeverage { leverage, .. } = a
        && s.max_leverage.is_some_and(|m| *leverage > m)
    {
        return Err("requested leverage exceeds session bound".into());
    }
    if let Some(cap) = &s.max_notional_usd {
        let cap = cap
            .parse::<f64>()
            .map_err(|_| "session max_notional_usd is invalid".to_string())?;
        if !cap.is_finite() || cap <= 0.0 {
            return Err("session max_notional_usd must be positive".into());
        }
        if let ExchangeAction::Order { orders, .. } = a {
            let notional = orders
                .iter()
                .filter(|o| !o.reduce_only)
                .map(|o| {
                    let price = o.price.parse::<f64>().unwrap_or(f64::INFINITY);
                    let size = o.size.parse::<f64>().unwrap_or(f64::INFINITY);
                    price * size
                })
                .sum::<f64>();
            if !notional.is_finite() || notional > cap {
                return Err("requested order notional exceeds session bound".into());
            }
        }
    }
    if !s.assets.is_empty() {
        let allowed = |asset: u32| s.assets.contains(&asset.to_string());
        let all_allowed = match a {
            ExchangeAction::Order { orders, .. } => orders.iter().all(|o| allowed(o.asset)),
            ExchangeAction::Cancel { cancels, .. } => cancels.iter().all(|o| allowed(o.asset)),
            ExchangeAction::CancelByCloid { cancels, .. } => {
                cancels.iter().all(|o| allowed(o.asset))
            }
            ExchangeAction::UpdateLeverage { asset, .. } => allowed(*asset),
            ExchangeAction::ScheduleCancel { .. } => true,
        };
        if !all_allowed {
            return Err("asset is outside the session allow-list".into());
        }
    }
    Ok(())
}
pub fn create_session(ctx: &Ctx, n: Network, w: String, body: &[u8]) -> DispatchResponse {
    let req = match serde_json::from_slice::<NewSession>(body) {
        Ok(x) => x,
        Err(e) => return invalid(format!("invalid new session body: {e}")),
    };
    if req.max_leverage.is_some_and(|x| !(1..=50).contains(&x)) {
        return invalid("max_leverage must be 1..=50");
    }
    if let Err(e) = valid_session_id(&req.id) {
        return invalid(e);
    }
    let now = petal::sdk::now_ms();
    let request_digest = hex::encode(sha3::Keccak256::digest(body));
    let pending_key = session_key(n, &w, &req.id, "pending.json");
    let pending = match load_json::<Pending>(pending_key.clone()) {
        Ok(x) => x,
        Err(e) => return e,
    };
    if let Some(existing) = pending.as_ref() {
        if existing.request_digest != request_digest {
            return invalid("session id is already bound to a different request body");
        }
        if existing.completed {
            return ok_write();
        }
        if existing
            .approval_expires_ms
            .is_some_and(|expires_ms| expires_ms <= now)
        {
            return invalid("session approval expired; create a fresh session id");
        }
    }
    let had_pending = pending.is_some();
    if let Some(cap) = &req.max_notional_usd {
        let parsed = match cap.parse::<f64>() {
            Ok(x) if x.is_finite() && x > 0.0 => x,
            _ => return invalid("max_notional_usd must be a positive decimal"),
        };
        if parsed > 1_000_000_000.0 {
            return invalid("max_notional_usd is unreasonably large");
        }
    }
    let session_assets = if pending.is_some() || req.assets.is_empty() {
        Vec::new()
    } else {
        let ids = match asset_ids(n) {
            Ok(x) => x,
            Err(e) => return e,
        };
        let mut normalized = Vec::with_capacity(req.assets.len());
        for asset in &req.assets {
            if let Ok(id) = asset.parse::<u32>() {
                normalized.push(id.to_string());
            } else if let Some(id) = ids.get(asset) {
                normalized.push(id.to_string());
            } else {
                return invalid(format!("unknown perpetual asset {asset}"));
            }
        }
        normalized
    };
    let key = match pending.as_ref() {
        Some(p) => match hex::decode(&p.key_hex) {
            Ok(x) if x.len() == 32 => x,
            _ => return backend("pending session agent key is invalid"),
        },
        None => match petal::sdk::random_bytes(32) {
            Ok(x) => x,
            Err(e) => return backend(e),
        },
    };
    let signer = match PrivateKeySigner::from_bytes(&key) {
        Ok(x) => x,
        Err(e) => return backend(format!("agent key generation failed: {e}")),
    };
    let generated_session = Session {
        schema: "bloom.hyperliquid_agent_session.v1".into(),
        network: if matches!(n, Network::Mainnet) {
            "mainnet".into()
        } else {
            "testnet".into()
        },
        wallet: w.clone(),
        id: req.id.clone(),
        agent_address: format!("{:#x}", signer.address()),
        agent_name: req
            .agent_name
            .unwrap_or_else(|| format!("bloom-{}", req.id)),
        created_ms: now,
        expires_ms: now.saturating_add(req.duration_ms.unwrap_or(3_600_000).min(86_400_000)),
        max_notional_usd: req.max_notional_usd,
        max_leverage: req.max_leverage,
        assets: session_assets,
        stopped: false,
        last_response: None,
        last_error: None,
    };
    let (session, nonce) = match pending {
        Some(p) => {
            if p.session.wallet != w
                || p.session.network
                    != if matches!(n, Network::Mainnet) {
                        "mainnet"
                    } else {
                        "testnet"
                    }
                || p.session.id != req.id
            {
                return invalid("pending session does not match this wallet, network, or id");
            }
            (p.session, p.nonce)
        }
        None => (generated_session, req.nonce.unwrap_or(now)),
    };
    let addr = session.agent_address.clone();
    if addr != format!("{:#x}", signer.address()) {
        return backend("pending session agent key does not match its address");
    }
    let (action, hash) =
        match protocol::approve_agent_hash(n, signer.address(), &session.agent_name, nonce) {
            Ok(x) => x,
            Err(e) => return invalid(e),
        };
    if !had_pending
        && let Err(e) = save_json_new(
            pending_key.clone(),
            &Pending {
                session: session.clone(),
                key_hex: hex::encode(&key),
                nonce,
                approval_expires_ms: None,
                request_digest: request_digest.clone(),
                completed: false,
            },
            true,
        )
    {
        return e;
    };
    let sig = match petal::sdk::sign(&w, hash.as_slice(), "hyperliquid.approve_agent") {
        Ok(petal::sdk::Sign::Signature(x)) => match protocol::SignatureJson::from_raw(&x) {
            Ok(x) => x,
            Err(e) => return invalid(e),
        },
        Ok(petal::sdk::Sign::Approval {
            action_id,
            ceremony_url,
            expires_ms,
        }) => {
            if let Err(e) = save_json(
                pending_key.clone(),
                &Pending {
                    session: session.clone(),
                    key_hex: hex::encode(&key),
                    nonce,
                    approval_expires_ms: Some(expires_ms),
                    request_digest: request_digest.clone(),
                    completed: false,
                },
                true,
            ) {
                return e;
            }
            return approval(
                ctx,
                "approve_agent",
                &json!({"action_id":action_id,"ceremony_url":ceremony_url,"expires_ms":expires_ms,"session":session.id}),
            );
        }
        Err(e) => return denied(format!("signing denied: {e}")),
    };
    if let Err(e) = save_json(
        pending_key.clone(),
        &Pending {
            session: session.clone(),
            key_hex: hex::encode(&key),
            nonce,
            approval_expires_ms: None,
            request_digest: request_digest.clone(),
            completed: false,
        },
        true,
    ) {
        return e;
    }
    match http_json(n, "/exchange", protocol::user_payload(action, nonce, sig)) {
        Ok(v) => {
            if let Err(e) = protocol::validate_exchange_response(&v) {
                return backend(e);
            }
            if let Err(e) = save_json(
                secret_key(&["sessions", &session.network, &w, &session.id, "agent_key"]),
                &key,
                true,
            ) {
                return e;
            }
            if let Err(e) = save_json(
                session_key(n, &w, &session.id, "session.json"),
                &session,
                false,
            ) {
                return e;
            }
            if let Err(e) = save_json(
                session_key(n, &w, &session.id, "last_response.json"),
                &v,
                false,
            ) {
                return e;
            }
            if let Err(e) = save_json(
                pending_key,
                &Pending {
                    session: session.clone(),
                    key_hex: hex::encode(&key),
                    nonce,
                    approval_expires_ms: None,
                    request_digest,
                    completed: true,
                },
                true,
            ) {
                return e;
            }
            let _ = addr;
            ok_write()
        }
        Err(e) => e,
    }
}

pub fn session_children(ctx: &Ctx) -> Vec<petal::Entry> {
    let Ok(n) = network(ctx) else {
        return Vec::new();
    };
    let Ok(w) = wallet(ctx) else {
        return Vec::new();
    };
    let prefix = state_key(&[
        "sessions",
        if matches!(n, Network::Mainnet) {
            "mainnet"
        } else {
            "testnet"
        },
        &w,
        "",
    ]);
    let ids = completed_session_ids(&prefix, petal::sdk::list(&prefix).unwrap_or_default());
    ids.into_iter()
        .map(|id| petal::Entry {
            name: id,
            kind: petal::EntryKind::Dir,
            mode: 0o755,
            size: Some(0),
            link_target: None,
        })
        .collect()
}
fn completed_session_ids(prefix: &str, keys: Vec<String>) -> Vec<String> {
    keys.into_iter()
        .filter_map(|key| {
            let id = key.strip_prefix(prefix)?.strip_suffix("/session.json")?;
            valid_session_id(id).ok().map(|()| id.to_owned())
        })
        .collect()
}
pub fn wallet_session_children(ctx: &Ctx) -> Vec<petal::Entry> {
    let mut out =
        crate::static_list(&[("new.json", false, true), ("last_error.json", false, true)]);
    out.extend(session_children(ctx));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bounded_session() -> Session {
        Session {
            schema: "bloom.hyperliquid_agent_session.v1".into(),
            network: "testnet".into(),
            wallet: "0x0000000000000000000000000000000000000001".into(),
            id: "test".into(),
            agent_address: "0x0000000000000000000000000000000000000002".into(),
            agent_name: "test".into(),
            created_ms: 1,
            expires_ms: u64::MAX,
            max_notional_usd: None,
            max_leverage: Some(3),
            assets: vec!["0".into()],
            stopped: false,
            last_response: None,
            last_error: None,
        }
    }

    #[test]
    fn session_policy_checks_every_batched_asset() {
        let action = ExchangeAction::Cancel {
            cancels: vec![
                protocol::CancelWire { asset: 0, oid: 1 },
                protocol::CancelWire { asset: 1, oid: 2 },
            ],
            fast: None,
        };
        assert_eq!(
            session_policy(&bounded_session(), &action),
            Err("asset is outside the session allow-list".into())
        );
    }

    #[test]
    fn session_policy_checks_leverage_asset_and_limit() {
        let disallowed_asset = ExchangeAction::UpdateLeverage {
            asset: 1,
            is_cross: true,
            leverage: 3,
        };
        assert_eq!(
            session_policy(&bounded_session(), &disallowed_asset),
            Err("asset is outside the session allow-list".into())
        );

        let excessive_leverage = ExchangeAction::UpdateLeverage {
            asset: 0,
            is_cross: true,
            leverage: 4,
        };
        assert_eq!(
            session_policy(&bounded_session(), &excessive_leverage),
            Err("requested leverage exceeds session bound".into())
        );
    }

    #[test]
    fn approval_nonce_keys_are_body_and_owner_scoped() {
        let wallet = "0x0000000000000000000000000000000000000001";
        let body = br#"{"action":{"type":"scheduleCancel"}}"#;
        let key = owner_nonce_key(Network::Testnet, wallet, "schedule_cancel.json", body);
        assert_eq!(
            key,
            owner_nonce_key(Network::Testnet, wallet, "schedule_cancel.json", body)
        );
        assert_ne!(
            key,
            owner_nonce_key(Network::Mainnet, wallet, "schedule_cancel.json", body)
        );
        assert_ne!(
            key,
            owner_nonce_key(
                Network::Testnet,
                "0x0000000000000000000000000000000000000002",
                "schedule_cancel.json",
                body,
            )
        );
    }

    #[test]
    fn write_success_uses_the_framework_write_variant() {
        assert_eq!(ok_write(), DispatchResponse::Write);
    }

    #[test]
    fn close_price_obeys_perpetual_tick_precision() {
        assert_eq!(close_price("42.123", true, 2).unwrap(), "63.185");
        assert_eq!(close_price("123456", false, 0).unwrap(), "61728");
        assert_eq!(canonical_abs_decimal("-1.2300"), "1.23");
    }

    #[test]
    fn completed_session_discovery_ignores_pending_and_nested_records() {
        let prefix = "state/sessions/testnet/wallet/";
        assert_eq!(
            completed_session_ids(
                prefix,
                vec![
                    format!("{prefix}alpha/pending.json"),
                    format!("{prefix}alpha/session.json"),
                    format!("{prefix}alpha/audit/event.jsonl"),
                    format!("{prefix}beta/session.json"),
                ],
            ),
            vec!["alpha".to_string(), "beta".to_string()]
        );
    }

    #[test]
    fn public_read_response_preserves_large_json_without_reserializing() {
        let raw = format!(r#"[{}]"#, vec![r#"{"value":"test"}"#; 50_000].join(",")).into_bytes();
        assert_eq!(
            read_json_response(200, raw.clone()),
            DispatchResponse::Read(raw)
        );
    }
}
