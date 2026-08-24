use alloy_primitives::Address;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use sha3::Digest;

use crate::protocol::{self, ExchangeAction, Network, SignSubmit};
use petal::{
    Ctx, DispatchResponse, HostStatus, HttpRequest, PayloadSignRequest, SdkError, SignOutcome,
    SignSelector,
};

const MAX_BODY: usize = 2 * 1024 * 1024;
const CLOSE_SLIPPAGE: f64 = 0.05;
// r000021 is the session-creation route that invokes derive_key. The Machine
// host requires the executing route to be part of the immutable derived-key
// scope, alongside the routes that later use the session key. Machine derives
// one route-specific reusable Sealed Approval from this installer-verified set
// before it reports the key ready; action routes reuse it by KeyRef.
const SESSION_KEY_ALLOWED_ROUTES: [&str; 7] = [
    "r000008", "r000009", "r000010", "r000013", "r000015", "r000019", "r000021",
];

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
    parse_wallet_id(p(ctx, "wallet")?).map_err(invalid)
}
pub fn parse_wallet_id(raw: &str) -> Result<String, String> {
    if raw.is_empty() || raw.len() > 128 || raw.chars().any(|c| c.is_control() || c == '/') {
        return Err("wallet id must be 1-128 characters without '/' or control characters".into());
    }
    Ok(raw.to_owned())
}
fn state_key(parts: &[&str]) -> String {
    format!("state/{}", parts.join("/"))
}
fn save_json(
    key: String,
    v: &(impl Serialize + ?Sized),
    secret: bool,
) -> Result<(), DispatchResponse> {
    let b = serde_json::to_vec(v).map_err(|e| backend(e.to_string()))?;
    petal::sdk::store_put(&key, &b, secret).map_err(|e| backend(e.message()))
}
fn save_json_new(
    key: String,
    v: &(impl Serialize + ?Sized),
    secret: bool,
) -> Result<(), DispatchResponse> {
    let b = serde_json::to_vec(v).map_err(|e| backend(e.to_string()))?;
    petal::sdk::store_put_new(&key, &b, secret).map_err(|e| backend(e.message()))
}
fn load_bytes_result(key: &str) -> Result<Option<Vec<u8>>, SdkError> {
    match petal::sdk::store_get(key, MAX_BODY) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(SdkError::Host(HostStatus::NotFound)) => Ok(None),
        Err(e) => Err(e),
    }
}
fn load_bytes(key: &str) -> Result<Option<Vec<u8>>, DispatchResponse> {
    load_bytes_result(key).map_err(|e| backend(e.message()))
}
fn load_secret_bytes(key: &str) -> Result<Option<Vec<u8>>, DispatchResponse> {
    petal::bindings::bloom::store::kv::get("secrets", key).map_err(backend)
}
fn load_json<T: for<'de> Deserialize<'de>>(key: String) -> Result<Option<T>, DispatchResponse> {
    let Some(b) = load_bytes(&key)? else {
        return Ok(None);
    };
    serde_json::from_slice(&b)
        .map(Some)
        .map_err(|e| backend(format!("stored state is invalid: {e}")))
}
fn load_secret_json<T: for<'de> Deserialize<'de>>(
    key: String,
) -> Result<Option<T>, DispatchResponse> {
    let Some(bytes) = load_secret_bytes(&key)? else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|e| backend(format!("stored secret state is invalid: {e}")))
}
fn http_raw(net: Network, path: &str, body: Value) -> Result<(u16, Vec<u8>), DispatchResponse> {
    let b = serde_json::to_vec(&body).map_err(|e| backend(e.to_string()))?;
    let response = petal::sdk::http_fetch(
        &HttpRequest {
            method: "POST".into(),
            url: format!("{}{path}", net.url()),
            headers: vec![("content-type".into(), "application/json".into())],
            body: b,
        },
        MAX_BODY,
    )
    .map_err(|e| backend(e.message()))?;
    Ok((response.status, response.body))
}
fn route_id(ctx: &Ctx) -> Result<&str, String> {
    ctx.params
        .iter()
        .find_map(|(name, value)| (name == "bloom.route_id").then_some(value.as_str()))
        .ok_or_else(|| "trusted Petal route id is unavailable".into())
}
fn sign_payload(
    ctx: &Ctx,
    wallet: &str,
    payload: &protocol::SigningPayload,
    operation_class: &str,
    approval_hint: Option<String>,
    key_ref_jcs: Option<Vec<u8>>,
) -> Result<SignOutcome, String> {
    let payload_digest = petal::payload_batch_digest(&[petal::PayloadSignItem {
        preimage: payload.preimage.clone(),
        claimed_hash: payload.hash.into(),
    }])
    .map_err(|error| error.message())?;
    let route = route_id(ctx)?;
    let nonce_digest = Sha256::digest(
        [
            ctx.package_hash.as_bytes(),
            route.as_bytes(),
            operation_class.as_bytes(),
            payload.hash.as_slice(),
        ]
        .concat(),
    );
    let claim = json!({
        "package_hash": ctx.package_hash,
        "route": route,
        "operation_class": operation_class,
        "crypto_suite": "secp256k1-keccak256-recoverable",
        "payload_digest": hex::encode(payload_digest),
        "ordered_hashes": [hex::encode(payload.hash)],
        "declared_debits": [],
        "declared_destinations": [],
        "declared_fee": {"kind": "none"},
        "nonce": hex::encode(&nonce_digest[..16]),
        "claim_assurance": {"kind": "machine_asserted"}
    });
    petal::sdk::sign_payload(&PayloadSignRequest {
        wallet: wallet.into(),
        preimage: payload.preimage.clone(),
        claimed_hash: payload.hash.into(),
        signature_algorithm: "secp256k1-keccak256-recoverable".into(),
        operation_class: operation_class.into(),
        petal_use_claim_jcs: serde_jcs::to_vec(&claim).map_err(|e| e.to_string())?,
        claim_assurance_evidence: None,
        approval_hint,
        action: None,
        advisory: None,
        selector: if key_ref_jcs.is_some() {
            SignSelector::Reusable
        } else {
            SignSelector::Exact
        },
        key_ref_jcs,
    })
    .map_err(|e| e.message())
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
    match load_bytes(&last_response_key(n, w)) {
        Ok(Some(bytes)) => DispatchResponse::Read(bytes),
        Ok(None) => invalid("no exchange response has been recorded"),
        Err(response) => response,
    }
}

pub fn validate_body_size(body: &[u8]) -> Result<(), DispatchResponse> {
    if body.len() > MAX_BODY {
        Err(invalid("request body is too large"))
    } else {
        Ok(())
    }
}

fn last_response_key(n: Network, w: &str) -> String {
    state_key(&[
        "exchange",
        if matches!(n, Network::Mainnet) {
            "mainnet"
        } else {
            "testnet"
        },
        w,
        "last_response.json",
    ])
}

fn save_pending(key: &str, nonce: u64, completed: bool) -> Result<(), DispatchResponse> {
    let existing = load_json::<PendingNonce>(key.to_owned())?;
    save_json(
        key.to_owned(),
        &PendingNonce {
            nonce,
            expires_ms: existing.as_ref().map_or(u64::MAX, |state| state.expires_ms),
            action_id: existing.and_then(|state| state.action_id),
            completed,
        },
        false,
    )
}

fn owner_sign_or_approval(
    ctx: &Ctx,
    w: &str,
    payload: &protocol::SigningPayload,
    intent: &str,
    pending_nonce_key: Option<&str>,
    nonce: u64,
    approval_kind: &str,
) -> Result<protocol::SignatureJson, DispatchResponse> {
    let approval_hint = match pending_nonce_key {
        Some(key) => load_json::<PendingNonce>(key.to_owned())?.and_then(|state| {
            (state.expires_ms > petal::sdk::now_ms())
                .then_some(state.action_id)
                .flatten()
        }),
        None => None,
    };
    match sign_payload(ctx, w, payload, intent, approval_hint, None) {
        Ok(SignOutcome::Signature(s)) => match protocol::SignatureJson::from_raw(&s) {
            Ok(x) => Ok(x),
            Err(e) => Err(invalid(e)),
        },
        Ok(SignOutcome::ApprovalPending {
            action_id,
            expires_ms,
        }) => {
            if let Some(key) = pending_nonce_key
                && let Err(e) = save_json(
                    key.to_owned(),
                    &PendingNonce {
                        nonce,
                        expires_ms,
                        action_id: Some(action_id.clone()),
                        completed: false,
                    },
                    false,
                )
            {
                return Err(e);
            }
            Err(approval(
                approval_kind,
                &json!({"action_id":action_id,"expires_ms":expires_ms}),
            ))
        }
        Err(e) => Err(denied(format!("signing denied: {e}"))),
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
    if let Err(error) = req.action.validate() {
        return invalid(error);
    }
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
    let payload =
        match protocol::l1_signing_payload(n, &req.action, nonce, vault, req.expires_after) {
            Ok(h) => h,
            Err(e) => return invalid(e),
        };
    let sig = match owner_sign_or_approval(
        ctx,
        &w,
        &payload,
        req.action.intent(),
        pending_nonce_key.as_deref(),
        nonce,
        "exchange",
    ) {
        Ok(sig) => sig,
        Err(response) => return response,
    };
    if let Some(key) = pending_nonce_key.as_ref()
        && let Err(e) = save_pending(key, nonce, false)
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
        && let Err(e) = save_pending(&key, nonce, true)
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
    let marker = hex::encode(sha3::Keccak256::digest(body));
    let nonce = reserve_nonce(
        &state_key(&[
            "exchange",
            "nonces",
            if matches!(n, Network::Mainnet) {
                "mainnet"
            } else {
                "testnet"
            },
            w,
        ]),
        &marker,
    )?;
    let candidate = PendingNonce {
        nonce,
        expires_ms: u64::MAX,
        action_id: None,
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

#[derive(Debug, Serialize, Deserialize)]
struct PendingNonce {
    nonce: u64,
    expires_ms: u64,
    #[serde(default)]
    action_id: Option<String>,
    #[serde(default)]
    completed: bool,
}
fn reserve_nonce(prefix: &str, marker: &str) -> Result<u64, DispatchResponse> {
    let now = petal::sdk::now_ms();
    for offset in 0..1024_u64 {
        let nonce = now.saturating_add(offset);
        let key = format!("{prefix}/{nonce}.json");
        match save_json_new(key.clone(), &marker, false) {
            Ok(()) => return Ok(nonce),
            Err(first_error) => match load_bytes(&key) {
                Ok(Some(_)) => continue,
                Ok(None) => return Err(first_error),
                Err(response) => return Err(response),
            },
        }
    }
    Err(backend("unable to reserve a unique Hyperliquid nonce"))
}
fn session_nonce(
    n: Network,
    w: &str,
    id: &str,
    action: &ExchangeAction,
    vault: Option<&str>,
    expires: Option<u64>,
    explicit: Option<u64>,
) -> Result<(u64, Option<String>, bool), DispatchResponse> {
    if let Some(nonce) = explicit {
        return Ok((nonce, None, false));
    }
    let digest = session_operation_digest(action, vault, expires)?;
    let key = session_key(n, w, id, &format!("operations/{digest}/nonce.json"));
    if let Some(pending) = load_json::<PendingNonce>(key.clone())? {
        return Ok((pending.nonce, Some(key), pending.completed));
    }
    let nonce = reserve_nonce(&session_key(n, w, id, "nonces"), &digest)?;
    let candidate = PendingNonce {
        nonce,
        expires_ms: u64::MAX,
        action_id: None,
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
fn session_operation_digest(
    action: &ExchangeAction,
    vault: Option<&str>,
    expires: Option<u64>,
) -> Result<String, DispatchResponse> {
    let encoded =
        rmp_serde::to_vec_named(&(action, vault, expires)).map_err(|e| backend(e.to_string()))?;
    Ok(hex::encode(sha3::Keccak256::digest(encoded)))
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
            if let Err(e) = save_json(last_response_key(n, &w), &v, false) {
                return e;
            }
            ok_write()
        }
        Err(e) => e,
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UsdSend {
    destination: String,
    amount: String,
    #[serde(default)]
    nonce: Option<u64>,
}
pub fn usd_send(ctx: &Ctx, n: Network, w: String, body: &[u8]) -> DispatchResponse {
    let req = match serde_json::from_slice::<UsdSend>(body) {
        Ok(x) => x,
        Err(e) => return invalid(format!("invalid usd_send body: {e}")),
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
    let (action, payload) = match protocol::usd_send_payload(n, dest, &req.amount, nonce) {
        Ok(x) => x,
        Err(e) => return invalid(e),
    };
    let sig = match owner_sign_or_approval(
        ctx,
        &w,
        &payload,
        "hyperliquid.usd_send",
        pending_nonce_key.as_deref(),
        nonce,
        "usd_send",
    ) {
        Ok(sig) => sig,
        Err(response) => return response,
    };
    if let Some(key) = pending_nonce_key.as_ref()
        && let Err(e) = save_pending(key, nonce, false)
    {
        return e;
    }
    match http_json(n, "/exchange", protocol::user_payload(action, nonce, sig)) {
        Ok(v) => {
            if let Err(e) = protocol::validate_exchange_response(&v) {
                return backend(e);
            }
            if let Err(e) = save_json(last_response_key(n, &w), &v, false) {
                return e;
            }
            if let Some(key) = pending_nonce_key
                && let Err(e) = save_pending(&key, nonce, true)
            {
                return e;
            }
            ok_write()
        }
        Err(e) => e,
    }
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UsdClassTransfer {
    amount: String,
    to_perp: bool,
    #[serde(default)]
    nonce: Option<u64>,
}
pub fn usd_class_transfer(ctx: &Ctx, n: Network, w: String, body: &[u8]) -> DispatchResponse {
    let req = match serde_json::from_slice::<UsdClassTransfer>(body) {
        Ok(x) => x,
        Err(e) => return invalid(format!("invalid usd_class_transfer body: {e}")),
    };
    if let Err(e) = protocol::validate_usdc_amount(&req.amount) {
        return invalid(e);
    }
    let (nonce, pending_nonce_key, completed) =
        match owner_nonce(n, &w, "usd_class_transfer.json", body, req.nonce) {
            Ok(x) => x,
            Err(e) => return e,
        };
    if completed {
        return ok_write();
    }
    let (action, payload) =
        match protocol::usd_class_transfer_payload(n, &req.amount, req.to_perp, nonce) {
            Ok(x) => x,
            Err(e) => return invalid(e),
        };
    let sig = match owner_sign_or_approval(
        ctx,
        &w,
        &payload,
        "hyperliquid.usd_class_transfer",
        pending_nonce_key.as_deref(),
        nonce,
        "usd_class_transfer",
    ) {
        Ok(sig) => sig,
        Err(response) => return response,
    };
    if let Some(key) = pending_nonce_key.as_ref()
        && let Err(e) = save_pending(key, nonce, false)
    {
        return e;
    }
    match http_json(n, "/exchange", protocol::user_payload(action, nonce, sig)) {
        Ok(v) => {
            if let Err(e) = protocol::validate_exchange_response(&v) {
                return backend(e);
            }
            if let Err(e) = save_json(last_response_key(n, &w), &v, false) {
                return e;
            }
            if let Some(key) = pending_nonce_key
                && let Err(e) = save_pending(&key, nonce, true)
            {
                return e;
            }
            ok_write()
        }
        Err(e) => e,
    }
}
fn approval(kind: &str, v: &Value) -> DispatchResponse {
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
    pub owner_address: String,
    pub id: String,
    pub agent_address: String,
    pub key_ref_jcs: Vec<u8>,
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
    nonce: u64,
    #[serde(default)]
    approval_expires_ms: Option<u64>,
    #[serde(default)]
    approval_action_id: Option<String>,
    #[serde(default)]
    request_digest: String,
    #[serde(default)]
    completed: bool,
}

fn request_session_key(
    wallet: &str,
    session_id: &str,
    lifetime_ms: u64,
) -> Result<petal::PetalKeyOutcome, DispatchResponse> {
    petal::sdk::derive_key(&petal::PetalKeyRequest {
        wallet_id: wallet.into(),
        key_slot: session_key_slot(session_id),
        allowed_routes: SESSION_KEY_ALLOWED_ROUTES
            .into_iter()
            .map(str::to_owned)
            .collect(),
        allowed_operation_classes: vec!["hyperliquid.agent_action".into()],
        allowed_crypto_suites: vec!["secp256k1-keccak256-recoverable".into()],
        maximum_lifetime_ms: lifetime_ms,
    })
    .map_err(|error| backend(error.message()))
}

fn session_key_slot(session_id: &str) -> String {
    let digest = Sha256::digest(
        [
            b"bloom-hyperliquid-session-key/v1\0".as_slice(),
            session_id.as_bytes(),
        ]
        .concat(),
    );
    format!("hyperliquid-{}", &hex::encode(digest)[..52])
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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

fn default_agent_name(session_id: &str) -> String {
    let readable = format!("bloom-{session_id}");
    if readable.chars().count() <= 16 {
        return readable;
    }
    let digest = hex::encode(sha3::Keccak256::digest(session_id.as_bytes()));
    format!("bloom-{}", &digest[..10])
}

fn validate_agent_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty() || name.chars().count() > 16 {
        Err("agent_name must contain between 1 and 16 characters")
    } else {
        Ok(())
    }
}

fn session_preflight(req: &NewSession) -> Result<String, String> {
    if req
        .max_leverage
        .is_some_and(|value| !(1..=50).contains(&value))
    {
        return Err("max_leverage must be 1..=50".into());
    }
    valid_session_id(&req.id)?;
    let agent_name = req
        .agent_name
        .clone()
        .unwrap_or_else(|| default_agent_name(&req.id));
    validate_agent_name(&agent_name).map_err(str::to_owned)?;
    Ok(agent_name)
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

fn retire_session_key(
    n: Network,
    w: &str,
    id: &str,
    _session: &Session,
) -> Result<(), DispatchResponse> {
    let pending_key = session_key(n, w, id, "pending.json");
    if let Some(mut pending) = load_secret_json::<Pending>(pending_key.clone())? {
        pending.completed = true;
        pending.session.stopped = true;
        save_json(pending_key, &pending, true)?;
    }
    Ok(())
}

fn active_session(n: Network, w: &str, id: &str) -> Result<Session, DispatchResponse> {
    let Some(session) = load_session(n, w, id)? else {
        return Err(petal::error(-1, "session not found"));
    };
    if session.stopped {
        retire_session_key(n, w, id, &session)?;
        return Err(denied("session is stopped"));
    }
    if session.expires_ms <= petal::sdk::now_ms() {
        retire_session_key(n, w, id, &session)?;
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
    if let Err(response) = retire_session_key(n, w, id, &session) {
        return response;
    }
    match save_json(session_key(n, w, id, "session.json"), &session, false) {
        Ok(()) => ok_write(),
        Err(response) => response,
    }
}

pub fn cancel_all_session(ctx: &Ctx, n: Network, w: &str, id: &str) -> DispatchResponse {
    let mut session = match active_session(n, w, id) {
        Ok(session) => session,
        Err(response) => return response,
    };
    session_cancel_all(ctx, n, w, id, &mut session)
}

pub fn close_all_session(ctx: &Ctx, n: Network, w: &str, id: &str) -> DispatchResponse {
    let mut session = match active_session(n, w, id) {
        Ok(session) => session,
        Err(response) => return response,
    };
    session_close_all(ctx, n, w, id, &mut session)
}

fn record_session_error(
    n: Network,
    w: &str,
    id: &str,
    s: &mut Session,
    nonce: u64,
    action_kind: &str,
    msg: &str,
) {
    s.last_error = Some(msg.to_owned());
    let _ = save_json(session_key(n, w, id, "session.json"), s, false);
    let _ = save_json(session_key(n, w, id, "last_error.json"), msg, false);
    let _ = append_audit(
        n,
        w,
        id,
        &json!({"time_ms":nonce,"event":"session_action_error","action":action_kind,"error":msg}),
    );
}

#[allow(clippy::too_many_arguments)]
fn session_submit(
    ctx: &Ctx,
    n: Network,
    w: &str,
    id: &str,
    s: &mut Session,
    action: ExchangeAction,
    vault: Option<Address>,
    vault_str: Option<String>,
    expires: Option<u64>,
    explicit_nonce: Option<u64>,
) -> DispatchResponse {
    if let Err(e) = action.validate() {
        return invalid(e);
    }
    if let Err(e) = session_policy(s, &action) {
        return denied(e);
    }
    if let Err(e) = verify_live_session_leverage(n, s, &action) {
        return e;
    }
    let (nonce, operation_key, completed) = match session_nonce(
        n,
        w,
        id,
        &action,
        vault_str.as_deref(),
        expires,
        explicit_nonce,
    ) {
        Ok(x) => x,
        Err(e) => return e,
    };
    if completed {
        return ok_write();
    }
    let signing_payload = match protocol::l1_signing_payload(n, &action, nonce, vault, expires) {
        Ok(x) => x,
        Err(e) => return invalid(e),
    };
    let sig = match sign_payload(
        ctx,
        w,
        &signing_payload,
        "hyperliquid.agent_action",
        None,
        Some(s.key_ref_jcs.clone()),
    ) {
        Ok(SignOutcome::Signature(x)) => match protocol::SignatureJson::from_raw(&x) {
            Ok(v) => v,
            Err(e) => return backend(e),
        },
        Ok(SignOutcome::ApprovalPending {
            action_id,
            expires_ms,
        }) => {
            return approval(
                "agent_action",
                &json!({"action_id": action_id, "expires_ms": expires_ms, "session": id}),
            );
        }
        Err(e) => return denied(format!("agent signing denied: {e}")),
    };
    let action_kind = action.kind();
    let payload = match protocol::exchange_payload(action, nonce, sig, vault_str, expires) {
        Ok(x) => x,
        Err(e) => return invalid(e),
    };
    match http_json(n, "/exchange", payload) {
        Ok(v) => {
            if let Err(e) = protocol::validate_exchange_response(&v) {
                record_session_error(n, w, id, s, nonce, action_kind, &e);
                return backend(e);
            }
            s.last_response = Some(v.clone());
            s.last_error = None;
            if let Err(e) = save_json(session_key(n, w, id, "session.json"), s, false) {
                return e;
            }
            if let Err(e) = save_json(session_key(n, w, id, "last_response.json"), &v, false) {
                return e;
            }
            let _ = petal::sdk::store_del(&session_key(n, w, id, "last_error.json"));
            let _ = append_audit(
                n,
                w,
                id,
                &json!({"time_ms":nonce,"event":"session_action","action":action_kind,"response":v}),
            );
            if let Some(key) = operation_key
                && let Err(e) = save_pending(&key, nonce, true)
            {
                return e;
            }
            ok_write()
        }
        Err(e) => {
            let msg = format!("{e:?}");
            record_session_error(n, w, id, s, nonce, action_kind, &msg);
            e
        }
    }
}

pub fn session_action_write(
    ctx: &Ctx,
    n: Network,
    w: &str,
    id: &str,
    req: SignSubmit,
) -> DispatchResponse {
    let mut s = match active_session(n, w, id) {
        Ok(session) => session,
        Err(response) => return response,
    };
    let vault = match req.vault_address.as_deref() {
        Some(x) => match protocol::parse_address(x) {
            Ok(a) => Some(a),
            Err(e) => return invalid(e),
        },
        None => None,
    };
    session_submit(
        ctx,
        n,
        w,
        id,
        &mut s,
        req.action,
        vault,
        req.vault_address,
        req.expires_after,
        req.nonce,
    )
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
    match petal::sdk::store_put_new(&key, &line, false) {
        Ok(()) => Ok(()),
        Err(e) => match load_bytes(&key) {
            Ok(Some(existing)) if existing == line => Ok(()),
            _ => Err(backend(e.message())),
        },
    }
}

pub fn read_audit(n: Network, w: &str, id: &str) -> Result<Vec<u8>, String> {
    let mut out = load_bytes_result(&session_key(n, w, id, "audit.jsonl"))
        .map_err(|e| e.message())?
        .unwrap_or_default();
    if out.len() > MAX_BODY {
        out.clear();
    }
    let prefix = session_key(n, w, id, "audit/");
    let mut keys = petal::sdk::store_list(&prefix, MAX_BODY).map_err(|e| e.message())?;
    keys.sort();
    for key in keys.iter().skip(keys.len().saturating_sub(1024)) {
        let Some(line) = load_bytes_result(key).map_err(|e| e.message())? else {
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
    ctx: &Ctx,
    n: Network,
    w: &str,
    id: &str,
    s: &mut Session,
    action: ExchangeAction,
) -> DispatchResponse {
    session_submit(ctx, n, w, id, s, action, None, None, None, None)
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
    ctx: &Ctx,
    n: Network,
    w: &str,
    id: &str,
    s: &mut Session,
) -> DispatchResponse {
    let open = match http_json(
        n,
        "/info",
        json!({"type":"openOrders","user":s.owner_address}),
    ) {
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
    session_agent_submit(ctx, n, w, id, s, action)
}
fn close_price(raw: &str, buy: bool, sz_decimals: u32) -> Result<String, String> {
    let x: f64 = raw
        .parse()
        .map_err(|_| format!("invalid market price {raw}"))?;
    if !x.is_finite() || x <= 0.0 {
        return Err("market price must be positive".into());
    };
    let y = if buy {
        x * (1.0 + CLOSE_SLIPPAGE)
    } else {
        x * (1.0 - CLOSE_SLIPPAGE)
    };
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
    ctx: &Ctx,
    n: Network,
    w: &str,
    id: &str,
    s: &mut Session,
) -> DispatchResponse {
    let state = match http_json(
        n,
        "/info",
        json!({"type":"clearinghouseState","user":s.owner_address}),
    ) {
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
    session_agent_submit(ctx, n, w, id, s, action)
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
            ExchangeAction::ScheduleCancel { .. } => false,
        };
        if !all_allowed {
            return Err("asset is outside the session allow-list".into());
        }
    }
    Ok(())
}

/// A session cap is meaningful only if the venue-side setting is bounded before
/// an agent signs an order. Hyperliquid retains leverage independently of the
/// Petal session, so checking only a proposed `updateLeverage` would leave an
/// existing cross-leverage setting usable by later orders.
fn verify_live_session_leverage(
    n: Network,
    session: &Session,
    action: &ExchangeAction,
) -> Result<(), DispatchResponse> {
    let Some(max_leverage) = session.max_leverage else {
        return Ok(());
    };
    let ExchangeAction::Order { orders, .. } = action else {
        return Ok(());
    };
    let required_assets = orders
        .iter()
        .filter(|order| !order.reduce_only)
        .map(|order| order.asset)
        .collect::<std::collections::BTreeSet<_>>();
    if required_assets.is_empty() {
        return Ok(());
    }
    let assets = asset_metadata(n)?;
    let names = assets
        .iter()
        .map(|(name, asset)| (asset.id, name.as_str()))
        .collect::<std::collections::BTreeMap<_, _>>();
    for asset in required_assets {
        let Some(name) = names.get(&asset) else {
            return Err(denied(
                "session order references an unknown perpetual asset",
            ));
        };
        let state = http_json(
            n,
            "/info",
            json!({
                "type": "activeAssetData",
                "user": session.owner_address,
                "coin": name
            }),
        )?;
        let leverage = active_asset_leverage(&state).ok_or_else(|| {
            denied(format!(
                "cannot verify venue leverage for {name}; set venue leverage to the session cap before submitting orders"
            ))
        })?;
        if leverage > max_leverage {
            return Err(denied("venue leverage exceeds session bound"));
        }
    }
    Ok(())
}

fn active_asset_leverage(state: &Value) -> Option<u32> {
    state
        .get("leverage")
        .and_then(|leverage| leverage.get("value"))
        .and_then(value_string)?
        .parse::<u32>()
        .ok()
}
/// The single wallet identity a session is created under.
///
/// Derivation, pending/session storage and owner signing all use this one
/// value, taken from the `[wallet]` route parameter. It was previously also
/// carried in the request body, which let the two disagree: a key could be
/// derived for one wallet while state was recorded and signing attempted under
/// another, and nothing rejected that until a lower layer refused the signature
/// — after the ceremony and key scope already existed.
///
/// Owner signing validates this as a Broker token, which must begin with a
/// lowercase ASCII letter, so an on-chain address can never sign. Reject that
/// here rather than several layers down as an unqualified permission error.
fn session_wallet_id(w: &str) -> Result<String, String> {
    let wallet_id = parse_wallet_id(w)?;
    if !wallet_id.starts_with(|c: char| c.is_ascii_lowercase()) {
        return Err("session routes are addressed by wallet id, not by on-chain address".into());
    }
    Ok(wallet_id)
}

pub fn create_session(ctx: &Ctx, n: Network, w: String, body: &[u8]) -> DispatchResponse {
    let req = match serde_json::from_slice::<NewSession>(body) {
        Ok(x) => x,
        Err(e) => return invalid(format!("invalid new session body: {e}")),
    };
    let wallet_id = match session_wallet_id(&w) {
        Ok(wallet_id) => wallet_id,
        Err(error) => return invalid(error),
    };
    let agent_name = match session_preflight(&req) {
        Ok(agent_name) => agent_name,
        Err(error) => return invalid(error),
    };
    let now = petal::sdk::now_ms();
    let request_digest = hex::encode(sha3::Keccak256::digest(body));
    let pending_key = session_key(n, &w, &req.id, "pending.json");
    let pending = match load_secret_json::<Pending>(pending_key.clone()) {
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
    let approval_hint = pending.as_ref().and_then(|state| {
        state
            .approval_expires_ms
            .is_some_and(|expires_ms| expires_ms > now)
            .then(|| state.approval_action_id.clone())
            .flatten()
    });
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
    let lifetime_ms = req.duration_ms.unwrap_or(3_600_000).min(86_400_000);
    let derived = match request_session_key(&wallet_id, &req.id, lifetime_ms) {
        Ok(petal::PetalKeyOutcome::Pending {
            operation_id,
            scope_digest,
        }) => {
            return approval(
                "derive_agent_key",
                &json!({
                    "operation_id": operation_id,
                    "scope_digest": scope_digest,
                    "session": req.id
                }),
            );
        }
        Ok(petal::PetalKeyOutcome::Ready {
            operation_id: _,
            scope_digest: _,
            key_ref_jcs,
            addresses,
        }) => {
            let Some(address) = addresses
                .into_iter()
                .find(|address| protocol::parse_address(address).is_ok())
            else {
                return backend("derived KeyRef has no EVM address");
            };
            (key_ref_jcs, address)
        }
        Err(response) => return response,
    };
    let generated_session = Session {
        schema: "bloom.hyperliquid_agent_session.v1".into(),
        network: if matches!(n, Network::Mainnet) {
            "mainnet".into()
        } else {
            "testnet".into()
        },
        wallet: w.clone(),
        // Filled in below by recovering the signer of the `approveAgent`
        // payload. It is deliberately not taken from the request: the session's
        // bounds are read from this address, so a caller-chosen value would let
        // the agent point its own limit checks at an unrelated account. The
        // session is only persisted after recovery succeeds, so no reader ever
        // observes the empty value.
        owner_address: String::new(),
        id: req.id.clone(),
        agent_address: derived.1.clone(),
        key_ref_jcs: derived.0.clone(),
        agent_name,
        created_ms: now,
        expires_ms: now.saturating_add(lifetime_ms),
        max_notional_usd: req.max_notional_usd,
        max_leverage: req.max_leverage,
        assets: session_assets,
        stopped: false,
        last_response: None,
        last_error: None,
    };
    let (mut session, nonce) = match pending {
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
    if session.key_ref_jcs != derived.0 || session.agent_address != derived.1 {
        return backend("pending session does not match the Signer-owned KeyRef");
    }
    let agent_address = match protocol::parse_address(&session.agent_address) {
        Ok(address) => address,
        Err(error) => return backend(error),
    };
    let (action, payload) =
        match protocol::approve_agent_payload(n, agent_address, &session.agent_name, nonce) {
            Ok(x) => x,
            Err(e) => return invalid(e),
        };
    if !had_pending
        && let Err(e) = save_json_new(
            pending_key.clone(),
            &Pending {
                session: session.clone(),
                nonce,
                approval_expires_ms: None,
                approval_action_id: None,
                request_digest: request_digest.clone(),
                completed: false,
            },
            true,
        )
    {
        return e;
    };
    let sig = match sign_payload(
        ctx,
        &w,
        &payload,
        "hyperliquid.approve_agent",
        approval_hint,
        None,
    ) {
        Ok(SignOutcome::Signature(raw)) => {
            // Bind the session to whoever actually signed. The venue recovers
            // this same address to decide which account the agent is approved
            // for, so it is the account the session's orders will execute on.
            match protocol::recover_signer(&payload.hash, &raw) {
                Ok(address) => session.owner_address = address,
                Err(e) => return backend(e),
            }
            match protocol::SignatureJson::from_raw(&raw) {
                Ok(x) => x,
                Err(e) => return invalid(e),
            }
        }
        Ok(SignOutcome::ApprovalPending {
            action_id,
            expires_ms,
        }) => {
            if let Err(e) = save_json(
                pending_key.clone(),
                &Pending {
                    session: session.clone(),
                    nonce,
                    approval_expires_ms: Some(expires_ms),
                    approval_action_id: Some(action_id.clone()),
                    request_digest: request_digest.clone(),
                    completed: false,
                },
                true,
            ) {
                return e;
            }
            return approval(
                "approve_agent",
                &json!({"action_id":action_id,"expires_ms":expires_ms,"session":session.id}),
            );
        }
        Err(e) => return denied(format!("signing denied: {e}")),
    };
    if let Err(e) = save_json(
        pending_key.clone(),
        &Pending {
            session: session.clone(),
            nonce,
            approval_expires_ms: None,
            approval_action_id: None,
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
                    nonce,
                    approval_expires_ms: None,
                    approval_action_id: None,
                    request_digest,
                    completed: true,
                },
                true,
            ) {
                return e;
            }
            ok_write()
        }
        Err(e) => e,
    }
}

pub fn session_children(ctx: &Ctx) -> Result<Vec<petal::RouteChild>, DispatchResponse> {
    let n = network(ctx)?;
    let w = wallet(ctx)?;
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
    let keys =
        petal::sdk::store_list(&prefix, MAX_BODY).map_err(|error| backend(error.message()))?;
    Ok(completed_session_ids(&prefix, keys)
        .into_iter()
        .map(petal::dir)
        .collect())
}
fn completed_session_ids(prefix: &str, keys: Vec<String>) -> Vec<String> {
    keys.into_iter()
        .filter_map(|key| {
            let id = key.strip_prefix(prefix)?.strip_suffix("/session.json")?;
            valid_session_id(id).ok().map(|()| id.to_owned())
        })
        .collect()
}
pub fn wallet_session_children(ctx: &Ctx) -> Result<Vec<petal::RouteChild>, DispatchResponse> {
    let mut out =
        crate::static_list(&[("new.json", false, true), ("last_error.json", false, false)]);
    out.extend(session_children(ctx)?);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_key_scope_includes_derivation_and_action_routes() {
        assert_eq!(
            SESSION_KEY_ALLOWED_ROUTES,
            [
                "r000008", "r000009", "r000010", "r000013", "r000015", "r000019", "r000021",
            ]
        );
    }

    fn bounded_session() -> Session {
        Session {
            schema: "bloom.hyperliquid_agent_session.v1".into(),
            network: "testnet".into(),
            wallet: "0x0000000000000000000000000000000000000001".into(),
            owner_address: "0x0000000000000000000000000000000000000001".into(),
            id: "test".into(),
            agent_address: "0x0000000000000000000000000000000000000002".into(),
            key_ref_jcs: br#"{"backend":"fixture"}"#.to_vec(),
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
    fn session_preflight_rejects_agent_names_before_host_calls() {
        assert_eq!(
            validate_agent_name(""),
            Err("agent_name must contain between 1 and 16 characters")
        );
        assert_eq!(
            validate_agent_name("seventeen-letters!"),
            Err("agent_name must contain between 1 and 16 characters")
        );
        assert_eq!(validate_agent_name("bloom-btc10f"), Ok(()));
        assert_eq!(default_agent_name("short"), "bloom-short");
        let generated = default_agent_name("manual-mainnet-integration-1785491512-23341");
        assert_eq!(generated.chars().count(), 16);
        assert!(generated.starts_with("bloom-"));

        let request = NewSession {
            id: "session".into(),
            duration_ms: None,
            agent_name: Some("agent-name-is-far-too-long".into()),
            max_notional_usd: None,
            max_leverage: None,
            assets: Vec::new(),
            nonce: None,
        };
        assert_eq!(
            session_preflight(&request),
            Err("agent_name must contain between 1 and 16 characters".into())
        );
    }

    #[test]
    fn session_key_slots_are_lowercase_broker_tokens_for_timestamped_ids() {
        let first = session_key_slot("bloom-eval-codex-20260814T150000Z-0123456789abcdef");
        let second = session_key_slot("bloom-eval-codex-20260814t150000z-0123456789abcdef");

        assert_eq!(first.len(), 64);
        assert!(first.starts_with("hyperliquid-"));
        assert!(
            first
                .bytes()
                .all(|byte| { byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' })
        );
        assert_ne!(first, second);
    }

    #[test]
    fn active_asset_leverage_requires_a_valid_value() {
        assert_eq!(
            active_asset_leverage(&json!({"leverage": {"type": "cross", "value": "20"}})),
            Some(20)
        );
        assert_eq!(
            active_asset_leverage(&json!({"leverage": {"type": "isolated", "value": 5}})),
            Some(5)
        );
        assert_eq!(active_asset_leverage(&json!({})), None);
        assert_eq!(
            active_asset_leverage(&json!({"leverage": {"value": "cross"}})),
            None
        );
    }

    #[test]
    fn agent_actions_produce_signer_payloads_without_local_key_material() {
        let actions = [
            serde_json::from_value(json!({
                "type": "order",
                "orders": [{
                    "a": 0, "b": true, "p": "100", "s": "0.01", "r": false,
                    "t": {"limit": {"tif": "Gtc"}}
                }],
                "grouping": "na"
            }))
            .unwrap(),
            ExchangeAction::Cancel {
                cancels: vec![protocol::CancelWire { asset: 0, oid: 42 }],
                fast: None,
            },
        ];

        for (offset, action) in actions.into_iter().enumerate() {
            let nonce = 1_700_000_000_000 + offset as u64;
            let payload =
                protocol::l1_signing_payload(Network::Mainnet, &action, nonce, None, None).unwrap();
            assert_eq!(
                payload.hash,
                protocol::l1_signing_hash(Network::Mainnet, &action, nonce, None, None).unwrap()
            );
            assert!(!payload.preimage.is_empty());
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
        assert_eq!(
            session_policy(
                &bounded_session(),
                &ExchangeAction::ScheduleCancel { time: Some(123) }
            ),
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
    fn session_operation_identity_includes_vault_and_expiry() {
        let action = ExchangeAction::ScheduleCancel { time: Some(123) };
        let base = session_operation_digest(&action, None, None).unwrap();
        assert_ne!(
            base,
            session_operation_digest(
                &action,
                Some("0x0000000000000000000000000000000000000001"),
                None
            )
            .unwrap()
        );
        assert_ne!(
            base,
            session_operation_digest(&action, None, Some(999_999)).unwrap()
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
    fn usd_class_transfer_nonce_state_cannot_collide_with_usd_send() {
        let wallet = "0x0000000000000000000000000000000000000001";
        let body = br#"{"amount":"1","to_perp":true}"#;
        assert_ne!(
            owner_nonce_key(Network::Mainnet, wallet, "usd_class_transfer.json", body),
            owner_nonce_key(Network::Mainnet, wallet, "send_asset.json", body)
        );
        assert_ne!(
            owner_nonce_key(Network::Mainnet, wallet, "usd_class_transfer.json", body),
            owner_nonce_key(Network::Testnet, wallet, "usd_class_transfer.json", body)
        );
        assert_ne!(
            owner_nonce_key(Network::Mainnet, wallet, "usd_class_transfer.json", body),
            owner_nonce_key(
                Network::Mainnet,
                wallet,
                "usd_class_transfer.json",
                br#"{"amount":"1","to_perp":false}"#
            )
        );
    }

    #[test]
    fn session_identity_comes_only_from_the_route_and_never_from_the_body() {
        // The body used to carry wallet_id alongside the [wallet] route
        // parameter. Because they were independent, a request could derive a
        // key for one wallet while recording state and signing under another,
        // and nothing rejected it until a lower layer refused the signature —
        // by which point a ceremony and key scope already existed for a wallet
        // the caller was not operating on. The field is gone, so the two can no
        // longer disagree; deny_unknown_fields keeps it from coming back.
        let with_wallet_id = br#"{"id":"s","wallet_id":"other-wallet"}"#;
        let rejected = serde_json::from_slice::<NewSession>(with_wallet_id);
        assert!(
            rejected.is_err(),
            "a body naming its own wallet must be rejected, not silently ignored"
        );

        // owner_address is gone for the same reason. It fed the venue reads
        // behind max_leverage, cancel_all and close_all, so a caller-chosen
        // value aimed those checks at an account the session had nothing to do
        // with: point it at an account sitting at 1x and the leverage bound
        // passed while the order executed on the real wallet. It is now
        // recovered from the owner's own approveAgent signature.
        let with_owner_address =
            br#"{"id":"s","owner_address":"0x0000000000000000000000000000000000000001"}"#;
        assert!(
            serde_json::from_slice::<NewSession>(with_owner_address).is_err(),
            "a body naming its own owner address must be rejected"
        );

        let accepted: NewSession =
            serde_json::from_slice(br#"{"id":"s"}"#).expect("the id alone is the supported shape");
        assert_eq!(accepted.id, "s");
    }

    #[test]
    fn session_wallet_id_rejects_an_address_before_any_host_call() {
        // Owner signing validates the wallet as a Broker token, which must
        // begin with a lowercase letter, so an address can never sign. This
        // guard runs before key derivation, so a request that could never
        // complete does not first create a ceremony and a key scope.
        assert_eq!(
            session_wallet_id("bloom-eval-hyperliquid").as_deref(),
            Ok("bloom-eval-hyperliquid")
        );

        for address in [
            "0x2425c1bdf231f37ebdeeea462a3f00970f52f06a",
            "0000000000000000000000000000000000000001",
        ] {
            let rejected = session_wallet_id(address);
            assert!(
                rejected.is_err(),
                "an address-shaped wallet must be rejected: {address}"
            );
            assert!(
                rejected.unwrap_err().contains("addressed by wallet id"),
                "the error must say which identifier belongs where"
            );
        }
    }

    #[test]
    fn usd_class_transfer_body_requires_amount_and_direction() {
        assert!(serde_json::from_slice::<UsdClassTransfer>(br#"{"amount":"1"}"#).is_err());
        assert!(serde_json::from_slice::<UsdClassTransfer>(br#"{"to_perp":true}"#).is_err());
        assert!(
            serde_json::from_slice::<UsdClassTransfer>(br#"{"amount":"1","toPerp":true}"#).is_err()
        );
        assert!(
            serde_json::from_slice::<UsdClassTransfer>(
                br#"{"amount":"1","to_perp":true,"destination":"0x00"}"#
            )
            .is_err()
        );
        let req =
            serde_json::from_slice::<UsdClassTransfer>(br#"{"amount":"1.5","to_perp":false}"#)
                .unwrap();
        assert_eq!(req.amount, "1.5");
        assert!(!req.to_perp);
        assert_eq!(req.nonce, None);
    }

    #[test]
    fn write_success_uses_the_framework_write_variant() {
        assert_eq!(ok_write(), DispatchResponse::Write);
    }

    #[test]
    fn close_price_uses_bounded_slippage_and_perpetual_tick_precision() {
        assert_eq!(close_price("42.123", true, 2).unwrap(), "44.23");
        assert_eq!(close_price("123456", false, 0).unwrap(), "117280");
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

    #[test]
    fn last_response_key_is_network_scoped() {
        assert_eq!(
            last_response_key(Network::Mainnet, "0xabc"),
            "state/exchange/mainnet/0xabc/last_response.json"
        );
        assert_eq!(
            last_response_key(Network::Testnet, "0xabc"),
            "state/exchange/testnet/0xabc/last_response.json"
        );
    }
}
