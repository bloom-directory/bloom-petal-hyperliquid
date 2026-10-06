use alloy_primitives::Address;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use sha3::Digest;

use crate::protocol::{self, ExchangeAction, Network, SignSubmit};
use crate::settings;
use petal::{
    Ctx, DispatchResponse, HostStatus, HttpRequest, PayloadSignRequest, SdkError, SignOutcome,
    SignSelector,
};

const MAX_BODY: usize = 2 * 1024 * 1024;
const CLOSE_SLIPPAGE: f64 = 0.05;
// r000026 is the session-creation route that invokes derive_key. The Machine
// host requires the executing route to be part of the immutable derived-key
// scope, alongside the routes that later use the session key. Machine derives
// one route-specific reusable Sealed Approval from this installer-verified set
// before it reports the key ready; action routes reuse it by KeyRef.
const SESSION_KEY_ALLOWED_ROUTES: [&str; 7] = [
    "r000009", "r000010", "r000011", "r000014", "r000020", "r000024", "r000026",
];
/// `[session]/builder_order.json`. Added to a session key's scope, together
/// with `BUILDER_ORDER_INTENT`, only when the session was created with a
/// builder bound; a session without one has no builder fee to authorize.
const SESSION_KEY_BUILDER_ORDER_ROUTE: &str = "r000008";

#[derive(Clone, Debug, PartialEq)]
struct ClaimEffects {
    declared_debits: Vec<Value>,
    declared_destinations: Vec<Value>,
    declared_fee: Value,
}

impl ClaimEffects {
    fn none() -> Self {
        Self {
            declared_debits: Vec::new(),
            declared_destinations: Vec::new(),
            declared_fee: json!({"kind": "none"}),
        }
    }

    fn usd_send(amount_micros: u64, destination: Address) -> Self {
        Self {
            declared_debits: vec![json!({
                "asset": {"chain": "hyperliquid", "asset": "usdc"},
                "amount": amount_micros.to_string(),
            })],
            declared_destinations: vec![json!({
                "chain": "hyperliquid",
                "destination": format!("{destination:#x}"),
            })],
            declared_fee: json!({"kind": "none"}),
        }
    }

    /// A withdrawal debits the gross amount from the Hyperliquid account and
    /// settles on the destination chain (Arbitrum). The Broker catalogues petal
    /// operation classes with a `none` fee asset, so the claim itself cannot
    /// carry the venue fee; the exact fee and expected net proceeds travel in
    /// the operation record and the signing advisory instead.
    fn withdraw(amount_micros: u64, destination: Address) -> Self {
        Self {
            declared_debits: vec![json!({
                "asset": {"chain": "hyperliquid", "asset": "usdc"},
                "amount": amount_micros.to_string(),
            })],
            declared_destinations: vec![json!({
                "chain": "arbitrum",
                "destination": format!("{destination:#x}"),
            })],
            declared_fee: json!({"kind": "none"}),
        }
    }

    /// An order that carries a per-order builder fee pays it to a third-party
    /// address the caller chose, so it is a real economic effect the owner's
    /// approval ceremony must see rather than `{"kind":"none"}`. Broker's
    /// `DeclaredFee` is a closed schema (`{"kind":"none"}` or
    /// `{"kind":"fee","chain","asset","amount"}`, `amount` a plain integer
    /// string) with no field for the fee's recipient, so the builder address
    /// itself cannot be carried here — only what will be charged. The
    /// recipient and rate are committed in the signed order payload and
    /// shown in the owner's advisory instead.
    fn builder_order_fee(fee_micros: u64) -> Self {
        Self {
            declared_debits: Vec::new(),
            declared_destinations: Vec::new(),
            declared_fee: json!({
                "kind": "fee",
                "chain": "hyperliquid",
                "asset": "usdc",
                "amount": fee_micros.to_string(),
            }),
        }
    }
}

/// Computes the claim effect for an owner- or session-signed order action,
/// naming the builder's fee exactly when the order carries one so it is never
/// signed under `ClaimEffects::none()`. The declared amount is an upper bound
/// (rounded up) on `notional * fee_tenths_bps`, from prices the request itself
/// fixes, so nothing fetched before signing can go stale:
///
/// - A buy fills at or below its limit, so its limit bounds it.
/// - A sell crossing the book fills at the resting bid, which no order price
///   caps from above, so a builder-bearing sell must be post-only (`Alo`):
///   the venue refuses it rather than let it cross, and as a maker it fills
///   at exactly its limit.
/// - Hyperliquid charges no builder fee on the buying side of spot trades, so
///   spot buys add nothing; an order of only spot buys is refused, since its
///   builder would earn nothing.
/// - A trigger order fills at the market once triggered, so it is refused.
///
/// Every other leg counts, reduce-only included. The venue computes and
/// deducts the exact fee.
fn order_claim_effects(action: &ExchangeAction) -> Result<ClaimEffects, String> {
    let ExchangeAction::Order {
        orders,
        builder: Some(builder),
        ..
    } = action
    else {
        return Ok(ClaimEffects::none());
    };
    protocol::parse_address(&builder.address)?;
    Ok(ClaimEffects::builder_order_fee(
        builder_fee_upper_bound_micros(orders, builder.fee_tenths_bps)?,
    ))
}

fn is_spot_buy(order: &protocol::OrderWire) -> bool {
    order.is_buy && order.asset >= protocol::SPOT_ASSET_ID_OFFSET
}

fn builder_fee_upper_bound_micros(
    orders: &[protocol::OrderWire],
    fee_tenths_bps: u32,
) -> Result<u64, String> {
    if orders.iter().all(is_spot_buy) {
        return Err(
            "Hyperliquid charges no builder fee on spot buys, so a builder on an order of only spot buys earns nothing; submit it without a builder through order.json".into(),
        );
    }
    let mut notional = 0.0_f64;
    for o in orders {
        let Some(limit_type) = &o.order_type.limit else {
            return Err(
                "a builder-bearing trigger order cannot be bounded: a stop or take-profit fills at the market once triggered, so its builder fee cannot be declared in advance; submit it without a builder or as a limit order".into(),
            );
        };
        if !o.is_buy && !matches!(limit_type.tif, protocol::TimeInForce::Alo) {
            return Err(
                "a builder-bearing sell must be post-only (tif \"Alo\"): a sell that crosses the book fills at the resting bid, which nothing in the order caps, so its builder fee cannot be bounded; a post-only sell fills at exactly its limit".into(),
            );
        }
        if is_spot_buy(o) {
            continue;
        }
        let (Ok(limit), Ok(size)) = (o.price.parse::<f64>(), o.size.parse::<f64>()) else {
            return Err("order price and size must be decimal numbers".into());
        };
        notional += limit * size;
    }
    if !notional.is_finite() {
        return Err("order notional is not a finite number".into());
    }
    Ok(
        (notional * 1_000_000.0 * f64::from(fee_tenths_bps) / 100_000.0)
            .ceil()
            .clamp(0.0, u64::MAX as f64) as u64,
    )
}

/// The ceremony advisory for an order that carries a builder fee, so the
/// owner sees the recipient and the rate rather than only an opaque hash.
fn builder_order_advisory_for(action: &ExchangeAction) -> Option<Vec<u8>> {
    let ExchangeAction::Order {
        orders,
        builder: Some(builder),
        ..
    } = action
    else {
        return None;
    };
    // Runs after `order_claim_effects` accepted the same action, so the bound
    // that produced the declared fee is the one shown here.
    let fee_micros = builder_fee_upper_bound_micros(orders, builder.fee_tenths_bps).ok()?;
    Some(builder_order_advisory(
        &builder.address,
        builder.fee_tenths_bps,
        fee_micros,
        orders.iter().any(is_spot_buy),
    ))
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
#[allow(clippy::too_many_arguments)]
fn sign_payload(
    ctx: &Ctx,
    wallet: &str,
    payload: &protocol::SigningPayload,
    operation_class: &str,
    approval_hint: Option<String>,
    key_ref_jcs: Option<Vec<u8>>,
    advisory: Option<Vec<u8>>,
    effects: ClaimEffects,
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
        "declared_debits": effects.declared_debits,
        "declared_destinations": effects.declared_destinations,
        "declared_fee": effects.declared_fee,
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
        advisory,
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

struct OwnerApproval<'a> {
    pending_nonce_key: Option<&'a str>,
    nonce: u64,
    kind: &'a str,
    advisory: Option<Vec<u8>>,
    effects: ClaimEffects,
}

fn owner_sign_or_approval(
    ctx: &Ctx,
    w: &str,
    payload: &protocol::SigningPayload,
    intent: &str,
    approval_ctx: OwnerApproval<'_>,
) -> Result<protocol::SignatureJson, DispatchResponse> {
    match sign_payload(
        ctx,
        w,
        payload,
        intent,
        None,
        None,
        approval_ctx.advisory,
        approval_ctx.effects,
    ) {
        Ok(SignOutcome::Signature(s)) => match protocol::SignatureJson::from_raw(&s) {
            Ok(x) => Ok(x),
            Err(e) => Err(invalid(e)),
        },
        Ok(SignOutcome::ApprovalPending {
            action_id,
            expires_ms,
        }) => {
            if let Some(key) = approval_ctx.pending_nonce_key
                && let Err(e) = save_json(
                    key.to_owned(),
                    &PendingNonce {
                        nonce: approval_ctx.nonce,
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
                approval_ctx.kind,
                &json!({"action_id":action_id,"expires_ms":expires_ms}),
            ))
        }
        Err(e) => Err(denied(format!("signing denied: {e}"))),
    }
}

/// The public owner address last recovered from one of this wallet's owner
/// signatures. Kept so a check that needs it, the builder-approval precheck,
/// can run before the next ceremony instead of only after it; the
/// authoritative check on the freshly recovered signer still runs after.
fn owner_address_key(w: &str) -> String {
    state_key(&["owner-address", w])
}

fn cached_owner_address(w: &str) -> Option<String> {
    load_json::<String>(owner_address_key(w)).ok().flatten()
}

fn remember_owner_address(w: &str, address: &str) {
    // Best effort: a failed write only costs a wasted ceremony on a later
    // call, never correctness, because the post-signature check still runs.
    let _ = save_json(owner_address_key(w), &address.to_owned(), false);
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
    let carries_builder = req.action.carries_builder();
    // Refuse an unapproved builder before the ceremony whenever the owner
    // address is already known from an earlier signature, so the owner is
    // not asked for a passkey tap the venue would then make pointless. The
    // authoritative check on the recovered signer still runs below.
    if carries_builder
        && let Some(owner_address) = cached_owner_address(&w)
        && let Err(e) = ensure_builder_fee_is_approved(n, &owner_address, &req.action)
    {
        return e;
    }
    let effects = match order_claim_effects(&req.action) {
        Ok(effects) => effects,
        Err(e) => return invalid(e),
    };
    let sig = match owner_sign_or_approval(
        ctx,
        &w,
        &payload,
        req.action.intent(),
        OwnerApproval {
            pending_nonce_key: pending_nonce_key.as_deref(),
            nonce,
            kind: "exchange",
            advisory: builder_order_advisory_for(&req.action),
            effects,
        },
    ) {
        Ok(sig) => sig,
        Err(response) => return response,
    };
    let owner_address = match protocol::recover_signer_from_json(&payload.hash, &sig) {
        Ok(address) => address,
        Err(e) => return backend(e),
    };
    remember_owner_address(&w, &owner_address);
    if carries_builder
        && let Err(e) = ensure_builder_fee_is_approved(n, &owner_address, &req.action)
    {
        return e;
    }
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
    let amount_micros = match protocol::usdc_amount_micros(&req.amount) {
        Ok(amount) => amount,
        Err(e) => return invalid(e),
    };
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
        OwnerApproval {
            pending_nonce_key: pending_nonce_key.as_deref(),
            nonce,
            kind: "usd_send",
            advisory: None,
            effects: ClaimEffects::usd_send(amount_micros, dest),
        },
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
        OwnerApproval {
            pending_nonce_key: pending_nonce_key.as_deref(),
            nonce,
            kind: "usd_class_transfer",
            advisory: None,
            // Moving USDC between engines owned by the same wallet has no external
            // destination and no net wallet debit.
            effects: ClaimEffects::none(),
        },
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
fn builder_address_override_key() -> String {
    state_key(&["settings", "builder-address"])
}

/// Reads the operator-set builder-address override, if any. Stored as plain
/// UTF-8 bytes, not JSON, in the "state" namespace — a builder address is
/// public data, not a credential, so it does not belong in the secret store.
fn builder_address_override() -> Result<Option<String>, DispatchResponse> {
    let bytes = load_bytes(&builder_address_override_key())?;
    Ok(bytes
        .and_then(|b| String::from_utf8(b).ok())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty()))
}

/// Reports which builder address `approve_builder_fee.json` would use as its
/// default today, and why, for `settings/status.json`.
pub fn builder_address_status() -> Result<settings::BuilderAddressStatus, DispatchResponse> {
    let store_override = builder_address_override()?;
    Ok(settings::default_builder_address_status(
        store_override.as_deref(),
    ))
}

/// Sets or clears the operator-set builder-address override for
/// `settings/builder-address`. An empty body clears the override, reverting
/// to this release's default, if any.
pub fn set_builder_address_override(body: &[u8]) -> DispatchResponse {
    let text = match std::str::from_utf8(body) {
        Ok(x) => x.trim(),
        Err(_) => return invalid("builder address must be UTF-8"),
    };
    let key = builder_address_override_key();
    if text.is_empty() {
        return match petal::sdk::store_del(&key) {
            Ok(()) => ok_write(),
            Err(e) => backend(e.message()),
        };
    }
    if let Err(e) = protocol::parse_address(text) {
        return invalid(e);
    }
    // Required lowercase for the same reason as the per-order and approval
    // builder fields: a stored override must match what orders will send
    // byte-for-byte, never silently normalized.
    if text != text.to_ascii_lowercase() {
        return invalid("builder address must be lowercase");
    }
    match petal::sdk::store_put(&key, text.as_bytes(), false) {
        Ok(()) => ok_write(),
        Err(e) => backend(e.message()),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApproveBuilderFee {
    #[serde(default)]
    builder: Option<String>,
    max_fee_tenths_bps: u32,
    #[serde(default)]
    nonce: Option<u64>,
}
/// Approves a maximum builder fee for a builder address. Hyperliquid requires
/// this to be signed by the main wallet, so — like `usd_class_transfer` — it
/// is deliberately absent from the delegated agent session surface: it is
/// reached only through `owner_sign_or_approval`, never through a session's
/// Signer-owned key.
pub fn approve_builder_fee(ctx: &Ctx, n: Network, w: String, body: &[u8]) -> DispatchResponse {
    let req = match serde_json::from_slice::<ApproveBuilderFee>(body) {
        Ok(x) => x,
        Err(e) => return invalid(format!("invalid approve_builder_fee body: {e}")),
    };
    let store_override = match builder_address_override() {
        Ok(x) => x,
        Err(e) => return e,
    };
    let resolved_builder = match settings::resolve_default_builder_address(
        req.builder.as_deref(),
        store_override.as_deref(),
    ) {
        Ok(x) => x,
        Err(e) => return invalid(e),
    };
    let builder_source = if req.builder.is_some() {
        "explicit in this request"
    } else {
        match settings::default_builder_address_status(store_override.as_deref()).source {
            settings::BuilderAddressSource::StoreOverride => {
                "operator override in settings/builder-address"
            }
            settings::BuilderAddressSource::ReleaseDefault => "this release's default",
            settings::BuilderAddressSource::Unconfigured => "unconfigured",
        }
    };
    let builder = match protocol::parse_address(&resolved_builder) {
        Ok(x) => x,
        Err(e) => return invalid(e),
    };
    // The per-order builder field is required lowercase so it matches this
    // approval byte-for-byte; require the approval's address the same way
    // rather than silently normalizing it, so the two can never drift.
    if resolved_builder != resolved_builder.to_ascii_lowercase() {
        return invalid("builder address must be lowercase");
    }
    if req.max_fee_tenths_bps > protocol::MAX_SPOT_BUILDER_FEE_TENTHS_BPS {
        return invalid(format!(
            "max_fee_tenths_bps must be 0..={}; 0 revokes the builder's approval",
            protocol::MAX_SPOT_BUILDER_FEE_TENTHS_BPS
        ));
    }
    let (nonce, pending_nonce_key, completed) =
        match owner_nonce(n, &w, "approve_builder_fee.json", body, req.nonce) {
            Ok(x) => x,
            Err(e) => return e,
        };
    if completed {
        return ok_write();
    }
    let max_fee_rate = protocol::builder_fee_max_rate_string(req.max_fee_tenths_bps);
    let (action, payload) =
        match protocol::approve_builder_fee_payload(n, builder, &max_fee_rate, nonce) {
            Ok(x) => x,
            Err(e) => return invalid(e),
        };
    let sig = match owner_sign_or_approval(
        ctx,
        &w,
        &payload,
        "hyperliquid.approve_builder_fee",
        OwnerApproval {
            pending_nonce_key: pending_nonce_key.as_deref(),
            nonce,
            kind: "approve_builder_fee",
            advisory: Some(builder_fee_approval_advisory(
                n,
                &resolved_builder,
                req.max_fee_tenths_bps,
                builder_source,
            )),
            // Approving a cap charges nothing by itself — only a later order
            // that actually carries a builder fee has an effect to declare —
            // and Broker's DeclaredFee schema has no field for a bare ceiling
            // in any case (only `{"kind":"fee",...}` or `{"kind":"none"}`).
            effects: ClaimEffects::none(),
        },
    ) {
        Ok(sig) => sig,
        Err(response) => return response,
    };
    if let Ok(owner_address) = protocol::recover_signer_from_json(&payload.hash, &sig) {
        remember_owner_address(&w, &owner_address);
    }
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
/// Venue-reported flat withdrawal fee at implementation time (Hyperliquid
/// exchange docs, 2026-09). Hyperliquid deducts it from the withdrawn amount,
/// so the destination receives the amount minus this fee; the venue may change
/// it, which is why a funded run must re-verify it rather than trust this
/// constant.
pub const WITHDRAWAL_FEE_MICROS: u64 = 1_000_000;

fn micros_decimal(micros: u64) -> String {
    let whole = micros / 1_000_000;
    let fraction = micros % 1_000_000;
    if fraction == 0 {
        format!("{whole}")
    } else {
        let mut frac = format!("{fraction:06}");
        while frac.ends_with('0') {
            frac.pop();
        }
        format!("{whole}.{frac}")
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Withdraw {
    destination: String,
    amount: String,
    #[serde(default)]
    nonce: Option<u64>,
}

fn validate_withdraw_request(req: &Withdraw) -> Result<(u64, Address), DispatchResponse> {
    let amount_micros = match protocol::usdc_amount_micros(&req.amount) {
        Ok(x) => x,
        Err(e) => return Err(invalid(e)),
    };
    let destination = match protocol::parse_address(&req.destination) {
        Ok(x) => x,
        Err(e) => return Err(invalid(e)),
    };
    if destination == Address::ZERO {
        return Err(invalid(
            "destination must be a non-zero external chain address",
        ));
    }
    if amount_micros <= WITHDRAWAL_FEE_MICROS {
        return Err(invalid(format!(
            "amount must exceed the venue withdrawal fee ({} USDC); the venue deducts the fee from the withdrawn amount",
            micros_decimal(WITHDRAWAL_FEE_MICROS)
        )));
    }
    Ok((amount_micros, destination))
}

fn withdraw_record_prefix(n: Network, w: &str) -> String {
    state_key(&[
        "exchange",
        if matches!(n, Network::Mainnet) {
            "mainnet"
        } else {
            "testnet"
        },
        w,
        "withdraw",
    ])
}

fn withdraw_operation_key(n: Network, w: &str, nonce: u64) -> String {
    format!("{}/{}.json", withdraw_record_prefix(n, w), nonce)
}

fn withdraw_submitted_key(n: Network, w: &str, nonce: u64) -> String {
    format!("{}/{}.submitted.json", withdraw_record_prefix(n, w), nonce)
}

/// The durable per-withdrawal operation record. `status` distinguishes what is
/// known about the venue submission; `status: "accepted"` is venue acceptance
/// only and is never settlement proof on the destination chain.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct WithdrawOperation {
    schema: String,
    network: String,
    wallet: String,
    destination: String,
    amount: String,
    amount_micros: String,
    fee_micros: String,
    nonce: u64,
    action: Value,
    payload_hash: String,
    status: String,
    #[serde(default)]
    response: Option<Value>,
    updated_ms: u64,
}

/// What the owner sees when approving a builder-fee cap. The recipient and
/// the ceiling are otherwise only inside the EIP-712 hash, so without this
/// the ceremony could not show which builder is being approved, or for how
/// much, or where that address came from.
fn builder_fee_approval_advisory(
    n: Network,
    builder: &str,
    cap_tenths_bps: u32,
    source: &str,
) -> Vec<u8> {
    let mut lines = vec![
        format!(
            "Approves builder {builder} to charge up to {} ({cap_tenths_bps} tenths of a basis point) of each fill's notional on this account's Hyperliquid {} orders.",
            protocol::builder_fee_max_rate_string(cap_tenths_bps),
            n.chain()
        ),
        format!("Builder address source: {source}."),
    ];
    if cap_tenths_bps == 0 {
        lines.push("A cap of 0% revokes this builder's approval.".to_owned());
    } else {
        lines.push(
            "Only orders that name this builder pay it; Hyperliquid enforces its own ceilings of 0.1% on perps and 1% on spot."
                .to_owned(),
        );
    }
    lines.join("\n").into_bytes()
}

/// What the owner sees when signing an order that carries a builder fee.
fn builder_order_advisory(
    builder: &str,
    fee_tenths_bps: u32,
    fee_micros: u64,
    has_spot_buys: bool,
) -> Vec<u8> {
    let legs = if has_spot_buys {
        "across all legs except spot buys, which pay no builder fee, reduce-only included"
    } else {
        "across all legs, reduce-only included"
    };
    [
        format!(
            "This order pays a builder fee to {builder}: {} ({fee_tenths_bps} tenths of a basis point) of each fill's notional.",
            protocol::builder_fee_max_rate_string(fee_tenths_bps)
        ),
        format!(
            "Declared upper bound: {} USDC {legs}; the venue deducts the exact fee from each fill.",
            micros_decimal(fee_micros)
        ),
    ]
    .join("\n")
    .into_bytes()
}

/// What the owner sees when approving a session created with a builder
/// bound: the one builder its orders may pay, and the most they may pay it.
fn session_builder_bound_advisory(builder: &str, cap_tenths_bps: u32) -> Vec<u8> {
    format!(
        "This session may submit builder-fee orders only to builder {builder}, at most {} ({cap_tenths_bps} tenths of a basis point) of each fill's notional; an order naming another builder or a higher fee is refused before signing.",
        protocol::builder_fee_max_rate_string(cap_tenths_bps)
    )
    .into_bytes()
}

fn withdraw_advisory(amount_micros: u64, destination: Address) -> Vec<u8> {
    let net = amount_micros.saturating_sub(WITHDRAWAL_FEE_MICROS);
    [
        format!(
            "Withdraws {} USDC from this account's Hyperliquid balance (withdraw3).",
            micros_decimal(amount_micros)
        ),
        format!(
            "Destination: {destination:#x} on Arbitrum; the venue reports roughly five minutes to finalize."
        ),
        format!(
            "Venue fee: {} USDC deducted by Hyperliquid from the withdrawn amount (venue-reported; verify before relying on it).",
            micros_decimal(WITHDRAWAL_FEE_MICROS)
        ),
        format!(
            "Expected net receipt: {} USDC. Venue acceptance is not settlement proof.",
            micros_decimal(net)
        ),
    ]
    .join("\n")
    .into_bytes()
}

/// What a retry of an exact withdrawal body may do, decided purely from the
/// durable state (stored record + submission marker) against the canonical
/// intent of the incoming request.
#[derive(Debug, PartialEq)]
enum WithdrawResume {
    /// The recorded accepted outcome is for this exact action: done.
    Completed,
    /// Continue the flow; `stale_marker` marks a submission marker left by an
    /// attempt that died before its POST and must be released first.
    Proceed {
        stale_marker: bool,
        record: Option<Box<WithdrawOperation>>,
    },
}

#[derive(Debug, PartialEq)]
enum WithdrawRefusal {
    IdentityMismatch,
    Uncertain,
    Unrecognized(String),
}

/// The submission marker plus record statuses form a small state machine with
/// one invariant: the record is durably marked `submitted` before any POST, so
/// a marker without a `submitted`/`accepted` record can only come from an
/// attempt that died (or failed to persist) before network I/O. That is what
/// makes `stale_marker` safe to release.
fn withdraw_resume(
    intent: &WithdrawOperation,
    stored: Option<WithdrawOperation>,
    marker_exists: bool,
) -> Result<WithdrawResume, WithdrawRefusal> {
    let Some(existing) = stored else {
        return Ok(WithdrawResume::Proceed {
            stale_marker: marker_exists,
            record: None,
        });
    };
    // The nonce is only a retry of the same operation if the recorded action
    // and payload hash are identical to this request's. Anything else is
    // nonce reuse across different withdrawals and must be rejected before
    // signing, submitting, or reporting a borrowed success.
    if existing.action != intent.action || existing.payload_hash != intent.payload_hash {
        return Err(WithdrawRefusal::IdentityMismatch);
    }
    match existing.status.as_str() {
        "accepted" => Ok(WithdrawResume::Completed),
        "submitted" => Err(WithdrawRefusal::Uncertain),
        "approval_pending" | "rejected" => Ok(WithdrawResume::Proceed {
            stale_marker: marker_exists,
            record: Some(Box::new(existing)),
        }),
        other => Err(WithdrawRefusal::Unrecognized(other.into())),
    }
}

fn withdraw_refusal(refusal: WithdrawRefusal, nonce: u64) -> DispatchResponse {
    match refusal {
        WithdrawRefusal::IdentityMismatch => invalid(format!(
            "withdrawal nonce {nonce} is already bound to a different withdrawal; retries must repeat the exact body that created it"
        )),
        WithdrawRefusal::Uncertain => backend(format!(
            "withdrawal nonce {nonce} was submitted but its outcome is uncertain; read withdrawals/{nonce}.json and the venue ledger instead of resubmitting"
        )),
        WithdrawRefusal::Unrecognized(status) => backend(format!(
            "withdrawal record has unrecognized status {status}; refusing to act"
        )),
    }
}

pub fn withdraw(ctx: &Ctx, n: Network, w: String, body: &[u8]) -> DispatchResponse {
    let req = match serde_json::from_slice::<Withdraw>(body) {
        Ok(x) => x,
        Err(e) => return invalid(format!("invalid withdraw body: {e}")),
    };
    let (amount_micros, dest) = match validate_withdraw_request(&req) {
        Ok(x) => x,
        Err(response) => return response,
    };
    let (nonce, pending_nonce_key, completed) =
        match owner_nonce(n, &w, "withdraw.json", body, req.nonce) {
            Ok(x) => x,
            Err(e) => return e,
        };
    let op_key = withdraw_operation_key(n, &w, nonce);
    let marker_key = withdraw_submitted_key(n, &w, nonce);
    let (action, payload) = match protocol::withdraw_payload(n, dest, &req.amount, nonce) {
        Ok(x) => x,
        Err(e) => return invalid(e),
    };
    // Build the canonical identity for THIS request before interpreting any
    // stored state, so a reused nonce can never borrow another operation's
    // outcome and a changed request can never be signed under an old record.
    let intent = WithdrawOperation {
        schema: "bloom.hyperliquid_withdraw.v1".into(),
        network: if matches!(n, Network::Mainnet) {
            "mainnet".into()
        } else {
            "testnet".into()
        },
        wallet: w.clone(),
        destination: format!("{dest:#x}"),
        amount: req.amount.clone(),
        amount_micros: amount_micros.to_string(),
        fee_micros: WITHDRAWAL_FEE_MICROS.to_string(),
        nonce,
        action: action.clone(),
        payload_hash: hex::encode(payload.hash),
        status: "approval_pending".into(),
        response: None,
        updated_ms: petal::sdk::now_ms(),
    };
    let stored = match load_json::<WithdrawOperation>(op_key.clone()) {
        Ok(x) => x,
        Err(response) => return response,
    };
    let marker_exists = match load_bytes(&marker_key) {
        Ok(bytes) => bytes.is_some(),
        Err(response) => return response,
    };
    let mut record = match withdraw_resume(&intent, stored, marker_exists) {
        Ok(resume) => match resume {
            WithdrawResume::Completed => return ok_write(),
            WithdrawResume::Proceed {
                stale_marker,
                record,
            } => {
                if stale_marker && let Err(e) = petal::sdk::store_del(&marker_key) {
                    return backend(e.message());
                }
                record
            }
        },
        Err(refusal) => return withdraw_refusal(refusal, nonce),
    };
    if completed {
        return ok_write();
    }
    match save_json_new(op_key.clone(), &intent, false) {
        Ok(()) => {}
        Err(first_error) => {
            // A concurrent replay may have created the record first; it must
            // describe this exact operation before it can be trusted.
            match load_json::<WithdrawOperation>(op_key.clone()) {
                Ok(Some(existing)) => {
                    if existing.action != intent.action
                        || existing.payload_hash != intent.payload_hash
                    {
                        return withdraw_refusal(WithdrawRefusal::IdentityMismatch, nonce);
                    }
                    record = Some(Box::new(existing));
                }
                Ok(None) => return first_error,
                Err(response) => return response,
            }
        }
    }
    let sig = match owner_sign_or_approval(
        ctx,
        &w,
        &payload,
        "hyperliquid.withdraw",
        OwnerApproval {
            pending_nonce_key: pending_nonce_key.as_deref(),
            nonce,
            kind: "withdrawal",
            advisory: Some(withdraw_advisory(amount_micros, dest)),
            effects: ClaimEffects::withdraw(amount_micros, dest),
        },
    ) {
        Ok(sig) => sig,
        Err(response) => return response,
    };
    if let Some(key) = pending_nonce_key.as_ref()
        && let Err(e) = save_pending(key, nonce, false)
    {
        return e;
    }
    // Claim the single submission slot before any network call: two replays of
    // the same body can never both reach POST.
    match save_json_new(marker_key.clone(), &action, false) {
        Ok(()) => {}
        Err(first_error) => match load_bytes(&marker_key) {
            Ok(Some(_)) => {
                return backend(format!(
                    "withdrawal nonce {nonce} already has a submission attempt; read withdrawals/{nonce}.json instead of resubmitting"
                ));
            }
            Ok(None) => return first_error,
            Err(response) => return response,
        },
    }
    // Durably mark the operation submitted BEFORE the POST. From this point on
    // the visible record must always allow for the possibility that the venue
    // processed the withdrawal, so a persistence failure here aborts the
    // submission instead of proceeding.
    let mut op = match record.take() {
        Some(record) => *record,
        None => intent,
    };
    op.status = "submitted".into();
    op.updated_ms = petal::sdk::now_ms();
    if let Err(e) = save_json(op_key.clone(), &op.clone(), false) {
        return backend(format!(
            "could not persist the submission state for withdrawal nonce {nonce}; refusing to submit: {e:?}"
        ));
    }
    match http_json(n, "/exchange", protocol::user_payload(action, nonce, sig)) {
        Ok(v) => {
            let (status, outcome) = match protocol::validate_exchange_response(&v) {
                Err(e) => ("rejected", backend(e)),
                Ok(()) => ("accepted", ok_write()),
            };
            op.status = status.into();
            op.response = Some(v.clone());
            op.updated_ms = petal::sdk::now_ms();
            if let Err(e) = save_json(op_key, &op, false) {
                return e;
            }
            if status == "rejected" {
                // Record the exact rejection, then release the submission slot
                // so an explicit retry of this body replays the identical
                // action instead of being stranded.
                let _ = petal::sdk::store_del(&marker_key);
                return outcome;
            }
            if let Err(e) = save_json(last_response_key(n, &w), &v, false) {
                return e;
            }
            if let Some(key) = pending_nonce_key
                && let Err(e) = save_pending(&key, nonce, true)
            {
                return e;
            }
            outcome
        }
        Err(e) => {
            // Network or HTTP failure: the record already durably says
            // "submitted", so the next attempt reconciles this operation
            // instead of creating or resubmitting anything.
            e
        }
    }
}

/// One withdrawal operation by its stable identity (the wallet-scoped nonce),
/// including the uncertain ones a latest-only view cannot surface.
pub fn withdraw_record(n: Network, w: &str, nonce: u64) -> DispatchResponse {
    match load_bytes(&withdraw_operation_key(n, w, nonce)) {
        Ok(Some(bytes)) => DispatchResponse::Read(bytes),
        Ok(None) => invalid(format!("no withdrawal record exists for nonce {nonce}")),
        Err(response) => response,
    }
}

/// Operation-record child names under the withdraw store prefix: numeric
/// `<nonce>.json` entries only, sorted. Submission markers are never listed.
fn withdraw_record_names(prefix: &str, keys: &[String]) -> Vec<String> {
    let mut names: Vec<(u64, String)> = keys
        .iter()
        .filter_map(|key| {
            let name = key.strip_prefix(prefix)?;
            let name = name.strip_prefix('/')?;
            let nonce = name.strip_suffix(".json")?;
            let nonce = nonce.parse::<u64>().ok()?;
            Some((nonce, format!("{nonce}.json")))
        })
        .collect();
    names.sort_unstable_by_key(|(nonce, _)| *nonce);
    names.into_iter().map(|(_, name)| name).collect()
}

pub fn withdraw_children(ctx: &Ctx) -> Result<Vec<petal::RouteChild>, DispatchResponse> {
    let n = network(ctx)?;
    let w = wallet(ctx)?;
    let prefix = withdraw_record_prefix(n, &w);
    let keys =
        petal::sdk::store_list(&prefix, MAX_BODY).map_err(|error| backend(error.message()))?;
    Ok(withdraw_record_names(&prefix, &keys)
        .into_iter()
        .map(petal::file)
        .collect())
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
    pub builder_address: Option<String>,
    pub max_builder_fee_tenths_bps: Option<u32>,
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
    builder_bound: bool,
) -> Result<petal::PetalKeyOutcome, DispatchResponse> {
    let (allowed_routes, allowed_operation_classes) = session_key_scope(builder_bound);
    petal::sdk::derive_key(&petal::PetalKeyRequest {
        wallet_id: wallet.into(),
        key_slot: session_key_slot(session_id),
        allowed_routes,
        allowed_operation_classes,
        allowed_crypto_suites: vec!["secp256k1-keccak256-recoverable".into()],
        maximum_lifetime_ms: lifetime_ms,
    })
    .map_err(|error| backend(error.message()))
}

/// The routes and operation classes a session key may sign for. A session
/// created with a builder bound additionally gets the builder-order route and
/// its fee-bearing class; every other session is scoped to the fee-free
/// `hyperliquid.agent_action` surface only.
fn session_key_scope(builder_bound: bool) -> (Vec<String>, Vec<String>) {
    let mut routes = SESSION_KEY_ALLOWED_ROUTES
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let mut classes = vec!["hyperliquid.agent_action".to_owned()];
    if builder_bound {
        routes.push(SESSION_KEY_BUILDER_ORDER_ROUTE.to_owned());
        classes.push(protocol::BUILDER_ORDER_INTENT.to_owned());
    }
    (routes, classes)
}

/// The class a session-signed action is authorized under. A builder-bearing
/// order declares a fee, so it signs under `BUILDER_ORDER_INTENT` rather than
/// the fee-free `hyperliquid.agent_action` every other session action uses.
fn session_operation_class(action: &ExchangeAction) -> &'static str {
    if action.carries_builder() {
        protocol::BUILDER_ORDER_INTENT
    } else {
        "hyperliquid.agent_action"
    }
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
    builder_address: Option<String>,
    #[serde(default)]
    max_builder_fee_tenths_bps: Option<u32>,
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
    match (&req.builder_address, req.max_builder_fee_tenths_bps) {
        (Some(address), Some(fee)) => {
            protocol::parse_address(address)?;
            if address != &address.to_ascii_lowercase() {
                return Err("builder_address must be lowercase".into());
            }
            // Delegated sessions never submit spot orders (session_policy
            // rejects spot asset ids unconditionally), so the session-level
            // bound is capped at the perp venue ceiling.
            if fee == 0 || fee > protocol::MAX_PERP_BUILDER_FEE_TENTHS_BPS {
                return Err(format!(
                    "max_builder_fee_tenths_bps must be 1..={}",
                    protocol::MAX_PERP_BUILDER_FEE_TENTHS_BPS
                ));
            }
        }
        (None, None) => {}
        _ => {
            return Err(
                "builder_address and max_builder_fee_tenths_bps must be set together".into(),
            );
        }
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

fn receipt_action_key(action: &str) -> Result<&'static str, DispatchResponse> {
    match action {
        "order" => Ok("order"),
        "cancel" => Ok("cancel"),
        _ => Err(invalid("receipt action must be order or cancel")),
    }
}

fn session_receipt_key(n: Network, w: &str, id: &str, cloid: &str, action: &str) -> String {
    session_key(
        n,
        w,
        id,
        &format!("receipts/{}/{action}.json", cloid.to_ascii_lowercase()),
    )
}

pub fn load_session_receipt(
    n: Network,
    w: &str,
    id: &str,
    cloid: &str,
    action: &str,
) -> Result<Option<Value>, DispatchResponse> {
    protocol::validate_cloid(cloid).map_err(invalid)?;
    let action = receipt_action_key(action)?;
    load_json(session_receipt_key(n, w, id, cloid, action))
}

#[derive(Debug, PartialEq)]
struct ReceiptTarget {
    item_index: usize,
    cloid: String,
    request: Value,
}

fn receipt_targets(action: &ExchangeAction) -> Result<Vec<ReceiptTarget>, DispatchResponse> {
    let mut targets = Vec::new();
    match action {
        ExchangeAction::Order { orders, .. } => {
            for (item_index, order) in orders.iter().enumerate() {
                if let Some(cloid) = order.cloid.as_deref() {
                    targets.push(ReceiptTarget {
                        item_index,
                        cloid: cloid.to_ascii_lowercase(),
                        request: serde_json::to_value(order).map_err(|e| backend(e.to_string()))?,
                    });
                }
            }
        }
        ExchangeAction::CancelByCloid { cancels, .. } => {
            for (item_index, cancel) in cancels.iter().enumerate() {
                targets.push(ReceiptTarget {
                    item_index,
                    cloid: cancel.cloid.to_ascii_lowercase(),
                    request: serde_json::to_value(cancel).map_err(|e| backend(e.to_string()))?,
                });
            }
        }
        _ => {}
    }
    Ok(targets)
}

fn receipt_item_count(action: &ExchangeAction) -> usize {
    match action {
        ExchangeAction::Order { orders, .. } => orders.len(),
        ExchangeAction::CancelByCloid { cancels, .. } => cancels.len(),
        _ => 0,
    }
}

fn receipt_action(action: &ExchangeAction) -> Option<&'static str> {
    match action {
        ExchangeAction::Order { .. } => Some("order"),
        ExchangeAction::CancelByCloid { .. } => Some("cancel"),
        _ => None,
    }
}

struct ReceiptBatch<'a> {
    action: &'a str,
    item_count: usize,
    targets: &'a [ReceiptTarget],
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct ReceiptReservation {
    schema: String,
    action: String,
    cloid: String,
    nonce: u64,
    item_index: usize,
    request: Value,
    operation_digest: String,
}

fn session_receipt_reservation_key(
    n: Network,
    w: &str,
    id: &str,
    cloid: &str,
    action: &str,
) -> String {
    session_key(
        n,
        w,
        id,
        &format!(
            "receipt_reservations/{}/{action}.json",
            cloid.to_ascii_lowercase()
        ),
    )
}

fn session_receipt_submission_key(
    n: Network,
    w: &str,
    id: &str,
    cloid: &str,
    action: &str,
) -> String {
    session_key(
        n,
        w,
        id,
        &format!(
            "receipt_reservations/{}/{action}.submitted.json",
            cloid.to_ascii_lowercase()
        ),
    )
}

fn receipt_reservations(
    nonce: u64,
    operation_digest: &str,
    batch: &ReceiptBatch<'_>,
) -> Vec<ReceiptReservation> {
    batch
        .targets
        .iter()
        .map(|target| ReceiptReservation {
            schema: "bloom.hyperliquid_session_action_receipt_reservation.v1".into(),
            action: batch.action.into(),
            cloid: target.cloid.clone(),
            nonce,
            item_index: target.item_index,
            request: target.request.clone(),
            operation_digest: operation_digest.into(),
        })
        .collect()
}

fn receipt_matches_reservation(receipt: &Value, reservation: &ReceiptReservation) -> bool {
    receipt.get("action") == Some(&Value::String(reservation.action.clone()))
        && receipt.get("cloid") == Some(&Value::String(reservation.cloid.clone()))
        && receipt.get("nonce") == Some(&Value::from(reservation.nonce))
        && receipt.get("item_index") == Some(&Value::from(reservation.item_index))
        && receipt.get("request") == Some(&reservation.request)
}

fn reserve_session_receipts(
    n: Network,
    w: &str,
    id: &str,
    reservations: &[ReceiptReservation],
) -> Result<bool, DispatchResponse> {
    if reservations.is_empty() {
        return Ok(false);
    }

    let mut finalized = 0;
    for reservation in reservations {
        let receipt_key = session_receipt_key(n, w, id, &reservation.cloid, &reservation.action);
        if let Some(receipt) = load_json::<Value>(receipt_key)? {
            let reservation_key =
                session_receipt_reservation_key(n, w, id, &reservation.cloid, &reservation.action);
            let stored_reservation = load_json::<ReceiptReservation>(reservation_key)?;
            if stored_reservation.as_ref() != Some(reservation)
                || !receipt_matches_reservation(&receipt, reservation)
            {
                return Err(backend(format!(
                    "immutable {} receipt already exists for cloid {}",
                    reservation.action, reservation.cloid
                )));
            }
            finalized += 1;
        }
    }
    if finalized == reservations.len() {
        return Ok(true);
    }
    if finalized != 0 {
        return Err(backend(
            "receipt batch is only partially finalized; refusing to resubmit",
        ));
    }

    for reservation in reservations {
        let key =
            session_receipt_reservation_key(n, w, id, &reservation.cloid, &reservation.action);
        match save_json_new(key.clone(), reservation, false) {
            Ok(()) => {}
            Err(first_error) => match load_json::<ReceiptReservation>(key)? {
                Some(existing) if existing == *reservation => {}
                Some(_) => {
                    return Err(backend(format!(
                        "{} receipt cloid {} is reserved by a different action",
                        reservation.action, reservation.cloid
                    )));
                }
                None => return Err(first_error),
            },
        }
    }
    Ok(false)
}

fn mark_session_receipt_submission(
    n: Network,
    w: &str,
    id: &str,
    reservations: &[ReceiptReservation],
) -> Result<(), DispatchResponse> {
    for reservation in reservations {
        let key = session_receipt_submission_key(n, w, id, &reservation.cloid, &reservation.action);
        match save_json_new(key.clone(), reservation, false) {
            Ok(()) => {}
            Err(first_error) => match load_json::<ReceiptReservation>(key)? {
                Some(_) => {
                    return Err(backend(format!(
                        "{} receipt submission was already attempted for cloid {}; refusing a possible duplicate",
                        reservation.action, reservation.cloid
                    )));
                }
                None => return Err(first_error),
            },
        }
    }
    Ok(())
}

fn save_session_receipts(
    n: Network,
    w: &str,
    id: &str,
    nonce: u64,
    batch: &ReceiptBatch<'_>,
    response: &Value,
) -> Result<(), DispatchResponse> {
    if batch.targets.is_empty() {
        return Ok(());
    }
    let statuses = response
        .pointer("/response/data/statuses")
        .and_then(Value::as_array)
        .ok_or_else(|| backend("successful receipt-producing response is missing statuses"))?;
    if statuses.len() != batch.item_count {
        return Err(backend(format!(
            "receipt-producing response has {} statuses for {} action items",
            statuses.len(),
            batch.item_count
        )));
    }
    for target in batch.targets {
        let mut correlated_response = response.clone();
        let correlated_statuses = correlated_response
            .pointer_mut("/response/data/statuses")
            .expect("statuses path was validated above");
        *correlated_statuses = Value::Array(vec![statuses[target.item_index].clone()]);
        let receipt = json!({
            "schema": "bloom.hyperliquid_session_action_receipt.v1",
            "network": if matches!(n, Network::Mainnet) { "mainnet" } else { "testnet" },
            "wallet": w,
            "session_id": id,
            "action": batch.action,
            "cloid": target.cloid,
            "nonce": nonce,
            "item_index": target.item_index,
            "request": target.request,
            "response": correlated_response,
        });
        let key = session_receipt_key(n, w, id, &target.cloid, batch.action);
        match save_json_new(key.clone(), &receipt, false) {
            Ok(()) => {}
            Err(first_error) => match load_json::<Value>(key)? {
                Some(existing) if existing == receipt => {}
                Some(_) => {
                    return Err(backend(format!(
                        "immutable {} receipt already exists for cloid {}",
                        batch.action, target.cloid
                    )));
                }
                None => return Err(first_error),
            },
        }
    }
    Ok(())
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
    if let Err(e) = ensure_builder_fee_is_approved(n, &s.owner_address, &action) {
        return e;
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
    let action_kind = action.kind();
    let receipt_action = receipt_action(&action);
    let receipt_item_count = receipt_item_count(&action);
    let receipt_targets = match receipt_targets(&action) {
        Ok(targets) => targets,
        Err(e) => return e,
    };
    let receipt_batch = receipt_action.map(|action| ReceiptBatch {
        action,
        item_count: receipt_item_count,
        targets: &receipt_targets,
    });
    let operation_digest = match session_operation_digest(&action, vault_str.as_deref(), expires) {
        Ok(digest) => digest,
        Err(e) => return e,
    };
    let receipt_reservations = receipt_batch.as_ref().map_or_else(Vec::new, |batch| {
        receipt_reservations(nonce, &operation_digest, batch)
    });
    match reserve_session_receipts(n, w, id, &receipt_reservations) {
        Ok(true) => {
            if let Some(key) = operation_key
                && let Err(e) = save_pending(&key, nonce, true)
            {
                return e;
            }
            return ok_write();
        }
        Ok(false) => {}
        Err(e) => return e,
    }
    let signing_payload = match protocol::l1_signing_payload(n, &action, nonce, vault, expires) {
        Ok(x) => x,
        Err(e) => return invalid(e),
    };
    let effects = match order_claim_effects(&action) {
        Ok(effects) => effects,
        Err(e) => return invalid(e),
    };
    let sig = match sign_payload(
        ctx,
        w,
        &signing_payload,
        session_operation_class(&action),
        None,
        Some(s.key_ref_jcs.clone()),
        None,
        effects,
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
    let payload = match protocol::exchange_payload(action, nonce, sig, vault_str, expires) {
        Ok(x) => x,
        Err(e) => return invalid(e),
    };
    if let Err(e) = mark_session_receipt_submission(n, w, id, &receipt_reservations) {
        return e;
    }
    match http_json(n, "/exchange", payload) {
        Ok(v) => {
            if let Err(e) = protocol::validate_exchange_response(&v) {
                record_session_error(n, w, id, s, nonce, action_kind, &e);
                return backend(e);
            }
            if let Some(receipt_batch) = receipt_batch
                && let Err(e) = save_session_receipts(n, w, id, nonce, &receipt_batch, &v)
            {
                return e;
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
    if let Err(error) = validate_session_target(&req) {
        return denied(error);
    }
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

fn validate_session_target(req: &SignSubmit) -> Result<(), String> {
    if req.vault_address.is_some() {
        return Err(
            "delegated sessions cannot target a vault or subaccount; create a session bound to that account instead"
                .into(),
        );
    }
    Ok(())
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
                return backend("Hyperliquid returned an open order without a coin");
            };
            let Some(asset) = ids.get(coin) else {
                if s.assets.is_empty() {
                    return denied(
                        "cancel_all cannot safely clean an unrestricted session containing a spot or unknown asset order",
                    );
                }
                continue;
            };
            if !session_allows_asset(s, *asset) {
                continue;
            }
            let Some(oid) = item
                .get("oid")
                .and_then(|v| v.as_u64().or_else(|| v.as_str()?.parse().ok()))
            else {
                return backend("Hyperliquid returned an open order without a valid order id");
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
    let is_perpetual = |asset: u32| asset < protocol::SPOT_ASSET_ID_OFFSET;
    let all_perpetual = match a {
        ExchangeAction::Order { orders, .. } => orders.iter().all(|o| is_perpetual(o.asset)),
        ExchangeAction::Cancel { cancels, .. } => cancels.iter().all(|o| is_perpetual(o.asset)),
        ExchangeAction::CancelByCloid { cancels, .. } => {
            cancels.iter().all(|o| is_perpetual(o.asset))
        }
        ExchangeAction::UpdateLeverage { asset, .. } => is_perpetual(*asset),
        ExchangeAction::ScheduleCancel { .. } => true,
    };
    if !all_perpetual {
        return Err("delegated sessions do not support spot asset ids".into());
    }
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
    // A per-order builder fee routes venue fee revenue to a third-party address
    // the agent chooses, so it is bounded like notional, leverage, and assets
    // are: an agent may only ever use the single builder and fee ceiling the
    // owner approved when the session was created.
    if let ExchangeAction::Order {
        builder: Some(builder),
        ..
    } = a
    {
        match (&s.builder_address, s.max_builder_fee_tenths_bps) {
            (Some(allowed), Some(cap))
                if *allowed == builder.address && builder.fee_tenths_bps <= cap => {}
            _ => {
                return Err("builder fee is outside the session's approved builder bound".into());
            }
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

/// Hyperliquid silently rejects a builder-fee order unless the account has
/// already signed a separate `approveBuilderFee` action authorizing at least
/// the requested rate for that builder. Checking this ourselves turns that
/// into a clear, actionable error instead of a venue-side rejection the
/// caller has no way to interpret.
fn ensure_builder_fee_is_approved(
    n: Network,
    account: &str,
    action: &ExchangeAction,
) -> Result<(), DispatchResponse> {
    let ExchangeAction::Order {
        builder: Some(builder),
        ..
    } = action
    else {
        return Ok(());
    };
    let response = http_json(
        n,
        "/info",
        json!({"type": "maxBuilderFee", "user": account, "builder": builder.address}),
    )?;
    let approved = response
        .as_u64()
        .ok_or_else(|| backend("Hyperliquid returned a non-numeric maxBuilderFee response"))?;
    if approved < u64::from(builder.fee_tenths_bps) {
        return Err(invalid(format!(
            "builder {} is not yet approved for a fee of {} tenths of a basis point (currently approved up to {approved}); call approve_builder_fee.json for this builder before placing this order",
            builder.address, builder.fee_tenths_bps
        )));
    }
    Ok(())
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
                if ids.values().any(|known| *known == id) {
                    normalized.push(id.to_string());
                } else {
                    return invalid(format!("unknown perpetual asset {asset}"));
                }
            } else if let Some(id) = ids.get(asset) {
                normalized.push(id.to_string());
            } else {
                return invalid(format!("unknown perpetual asset {asset}"));
            }
        }
        normalized
    };
    let lifetime_ms = req.duration_ms.unwrap_or(3_600_000).min(86_400_000);
    let derived = match request_session_key(
        &wallet_id,
        &req.id,
        lifetime_ms,
        req.builder_address.is_some(),
    ) {
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
        builder_address: req.builder_address,
        max_builder_fee_tenths_bps: req.max_builder_fee_tenths_bps,
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
    let builder_bound_advisory =
        match (&session.builder_address, session.max_builder_fee_tenths_bps) {
            (Some(builder), Some(cap)) => Some(session_builder_bound_advisory(builder, cap)),
            _ => None,
        };
    let sig = match sign_payload(
        ctx,
        &w,
        &payload,
        "hyperliquid.approve_agent",
        approval_hint,
        None,
        builder_bound_advisory,
        ClaimEffects::none(),
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
                "r000009", "r000010", "r000011", "r000014", "r000020", "r000024", "r000026",
            ]
        );
        assert_eq!(SESSION_KEY_BUILDER_ORDER_ROUTE, "r000008");
    }

    #[test]
    fn session_key_scope_adds_the_builder_order_surface_only_with_a_bound() {
        let (routes, classes) = session_key_scope(false);
        assert_eq!(routes, SESSION_KEY_ALLOWED_ROUTES);
        assert_eq!(classes, ["hyperliquid.agent_action"]);

        let (routes, classes) = session_key_scope(true);
        assert_eq!(routes.len(), SESSION_KEY_ALLOWED_ROUTES.len() + 1);
        assert_eq!(
            routes.last().map(String::as_str),
            Some(SESSION_KEY_BUILDER_ORDER_ROUTE)
        );
        assert_eq!(
            classes,
            ["hyperliquid.agent_action", protocol::BUILDER_ORDER_INTENT]
        );
    }

    #[test]
    fn session_actions_sign_under_the_builder_order_class_only_with_a_builder() {
        let plain: ExchangeAction = serde_json::from_value(json!({
            "type": "order",
            "orders": [{"a": 0, "b": true, "p": "1", "s": "1", "r": false, "t": {"limit": {"tif": "Gtc"}}}],
            "grouping": "na"
        }))
        .unwrap();
        assert_eq!(session_operation_class(&plain), "hyperliquid.agent_action");
        let with_builder: ExchangeAction = serde_json::from_value(json!({
            "type": "order",
            "orders": [{"a": 0, "b": true, "p": "1", "s": "1", "r": false, "t": {"limit": {"tif": "Gtc"}}}],
            "grouping": "na",
            "builder": {"b": "0x0000000000000000000000000000000000000001", "f": 10}
        }))
        .unwrap();
        assert_eq!(
            session_operation_class(&with_builder),
            protocol::BUILDER_ORDER_INTENT
        );
        let cancel: ExchangeAction = serde_json::from_value(json!({
            "type": "cancel",
            "cancels": [{"a": 0, "o": 1}]
        }))
        .unwrap();
        assert_eq!(session_operation_class(&cancel), "hyperliquid.agent_action");
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
            builder_address: None,
            max_builder_fee_tenths_bps: None,
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
            builder_address: None,
            max_builder_fee_tenths_bps: None,
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
    fn usd_send_claim_effects_bind_amount_and_destination() {
        let destination =
            protocol::parse_address("0x00000000000000000000000000000000000000aa").unwrap();
        let effects = ClaimEffects::usd_send(1_250_000, destination);
        assert_eq!(
            effects.declared_debits,
            vec![json!({
                "asset": {"chain": "hyperliquid", "asset": "usdc"},
                "amount": "1250000",
            })]
        );
        assert_eq!(
            effects.declared_destinations,
            vec![json!({
                "chain": "hyperliquid",
                "destination": "0x00000000000000000000000000000000000000aa",
            })]
        );
        assert_eq!(effects.declared_fee, json!({"kind": "none"}));
    }

    fn order_action_with_builder(address: &str, fee_tenths_bps: u32) -> ExchangeAction {
        serde_json::from_value(json!({
            "type": "order",
            "orders": [{
                "a": 0, "b": true, "p": "100", "s": "0.01", "r": false,
                "t": {"limit": {"tif": "Gtc"}}
            }],
            "grouping": "na",
            "builder": {"b": address, "f": fee_tenths_bps}
        }))
        .unwrap()
    }

    #[test]
    fn order_claim_effects_name_the_builder_and_fee_only_when_present() {
        let cancel = ExchangeAction::Cancel {
            cancels: vec![protocol::CancelWire { asset: 0, oid: 42 }],
            fast: None,
        };
        assert_eq!(order_claim_effects(&cancel).unwrap(), ClaimEffects::none());

        let plain_order: ExchangeAction = serde_json::from_value(json!({
            "type": "order",
            "orders": [{
                "a": 0, "b": true, "p": "100", "s": "0.01", "r": false,
                "t": {"limit": {"tif": "Gtc"}}
            }],
            "grouping": "na"
        }))
        .unwrap();
        assert_eq!(
            order_claim_effects(&plain_order).unwrap(),
            ClaimEffects::none()
        );

        // notional = 100 * 0.01 = 1.0 USDC; fee = 1_000_000 micros * 10 / 100_000 = 100 micros
        let builder_order =
            order_action_with_builder("0x0000000000000000000000000000000000000001", 10);
        let effects = order_claim_effects(&builder_order).unwrap();
        assert!(effects.declared_debits.is_empty());
        assert!(effects.declared_destinations.is_empty());
        assert_eq!(
            effects.declared_fee,
            json!({
                "kind": "fee",
                "chain": "hyperliquid",
                "asset": "usdc",
                "amount": "100",
            })
        );
    }

    #[test]
    fn order_claim_effects_fee_includes_reduce_only_legs() {
        let action: ExchangeAction = serde_json::from_value(json!({
            "type": "order",
            "orders": [
                {"a": 0, "b": true, "p": "100", "s": "0.01", "r": false, "t": {"limit": {"tif": "Gtc"}}},
                {"a": 0, "b": true, "p": "200", "s": "0.5", "r": true, "t": {"limit": {"tif": "Gtc"}}},
            ],
            "grouping": "na",
            "builder": {"b": "0x0000000000000000000000000000000000000001", "f": 10}
        }))
        .unwrap();
        // Hyperliquid charges the builder fee on every fill of an order that
        // names a builder, reduce-only legs included, so both legs count:
        // (1 + 100) notional at 1 bp is 10100 micro-USDC. The session
        // max_notional_usd check still excludes reduce-only legs; that is a
        // different bound with a different purpose.
        assert_eq!(
            order_claim_effects(&action).unwrap().declared_fee,
            json!({"kind": "fee", "chain": "hyperliquid", "asset": "usdc", "amount": "10100"})
        );
    }

    fn builder_order(legs: Value) -> ExchangeAction {
        serde_json::from_value(json!({
            "type": "order",
            "orders": legs,
            "grouping": "na",
            "builder": {"b": "0x0000000000000000000000000000000000000001", "f": 10}
        }))
        .unwrap()
    }

    fn declared_amount(action: &ExchangeAction) -> Result<Value, String> {
        order_claim_effects(action).map(|effects| effects.declared_fee["amount"].clone())
    }

    #[test]
    fn a_builder_bearing_sell_must_be_post_only() {
        // A GTC or IOC sell at limit 100 crosses into bids at 200 and fills
        // at 200: the venue charges 200 * 1 bp = 20000 micro-USDC, above any
        // bound the request or a pre-signing mid could give. It is refused.
        for tif in ["Gtc", "Ioc"] {
            let action = builder_order(json!([
                {"a": 0, "b": false, "p": "100", "s": "1", "r": false, "t": {"limit": {"tif": tif}}}
            ]));
            let err = declared_amount(&action).unwrap_err();
            assert!(err.contains("post-only"), "{err}");
            assert!(builder_order_advisory_for(&action).is_none());
        }
        // Post-only, the same sell can only rest and fill at exactly 100,
        // however far bids later rise: 100 * 1 bp = 10000 micro-USDC.
        let post_only = builder_order(json!([
            {"a": 0, "b": false, "p": "100", "s": "1", "r": false, "t": {"limit": {"tif": "Alo"}}}
        ]));
        assert_eq!(declared_amount(&post_only).unwrap(), "10000");
        // Buys keep any time in force: they fill at or below their limit.
        let ioc_buy = builder_order(json!([
            {"a": 0, "b": true, "p": "100", "s": "1", "r": false, "t": {"limit": {"tif": "Ioc"}}}
        ]));
        assert_eq!(declared_amount(&ioc_buy).unwrap(), "10000");
    }

    #[test]
    fn spot_buys_pay_no_builder_fee() {
        let spot = protocol::SPOT_ASSET_ID_OFFSET;
        // Only spot buys: the builder would earn nothing, so it is refused
        // rather than signed with a meaningless zero fee.
        let only_spot_buys = builder_order(json!([
            {"a": spot, "b": true, "p": "10", "s": "5", "r": false, "t": {"limit": {"tif": "Gtc"}}},
            {"a": spot + 1, "b": true, "p": "2", "s": "50", "r": false, "t": {"limit": {"tif": "Ioc"}}}
        ]));
        let err = declared_amount(&only_spot_buys).unwrap_err();
        assert!(err.contains("no builder fee on spot buys"), "{err}");
        assert!(builder_order_advisory_for(&only_spot_buys).is_none());

        // Mixed: the spot buy (10 * 5 = 50) adds nothing; the post-only spot
        // sell (20 * 3 = 60) and the perp buy (100 * 1 = 100) do, so the bound
        // is 160 * 1 bp = 16000 micro-USDC.
        let mixed = builder_order(json!([
            {"a": spot, "b": true, "p": "10", "s": "5", "r": false, "t": {"limit": {"tif": "Gtc"}}},
            {"a": spot, "b": false, "p": "20", "s": "3", "r": false, "t": {"limit": {"tif": "Alo"}}},
            {"a": 0, "b": true, "p": "100", "s": "1", "r": false, "t": {"limit": {"tif": "Gtc"}}}
        ]));
        assert_eq!(declared_amount(&mixed).unwrap(), "16000");
        let advisory = String::from_utf8(builder_order_advisory_for(&mixed).unwrap()).unwrap();
        assert!(advisory.contains("0.016 USDC"), "{advisory}");
        assert!(advisory.contains("except spot buys"), "{advisory}");

        // A spot sell must still be post-only.
        let spot_gtc_sell = builder_order(json!([
            {"a": spot, "b": false, "p": "20", "s": "3", "r": false, "t": {"limit": {"tif": "Gtc"}}}
        ]));
        assert!(
            declared_amount(&spot_gtc_sell)
                .unwrap_err()
                .contains("post-only")
        );
    }

    #[test]
    fn a_builder_bearing_trigger_order_is_refused() {
        // A take-profit with limit 190000 and trigger 200000 fills at the
        // market once triggered; its limit does not bound the fee the venue
        // would charge on such a fill, so the request is refused.
        for (is_buy, is_market) in [(false, false), (false, true), (true, false)] {
            let action: ExchangeAction = serde_json::from_value(json!({
                "type": "order",
                "orders": [{
                    "a": 0, "b": is_buy, "p": "190000", "s": "1", "r": false,
                    "t": {"trigger": {"isMarket": is_market, "triggerPx": "200000", "tpsl": "tp"}}
                }],
                "grouping": "na",
                "builder": {"b": "0x0000000000000000000000000000000000000001", "f": 10}
            }))
            .unwrap();
            let err = order_claim_effects(&action).unwrap_err();
            assert!(err.contains("trigger order cannot be bounded"), "{err}");
            assert!(builder_order_advisory_for(&action).is_none());
        }
        // The same order without a builder declares no fee and is not the
        // fee bound's concern.
        let plain: ExchangeAction = serde_json::from_value(json!({
            "type": "order",
            "orders": [{
                "a": 0, "b": false, "p": "190000", "s": "1", "r": false,
                "t": {"trigger": {"isMarket": false, "triggerPx": "200000", "tpsl": "tp"}}
            }],
            "grouping": "na"
        }))
        .unwrap();
        assert_eq!(order_claim_effects(&plain).unwrap(), ClaimEffects::none());
    }

    #[test]
    fn builder_advisories_name_the_recipient_and_the_rate() {
        let builder = "0x0000000000000000000000000000000000000001";
        let approval = String::from_utf8(builder_fee_approval_advisory(
            Network::Testnet,
            builder,
            10,
            "explicit in this request",
        ))
        .unwrap();
        assert!(approval.contains(builder));
        assert!(approval.contains("0.01%"));
        assert!(approval.contains("10 tenths of a basis point"));
        assert!(approval.contains("explicit in this request"));
        let revoke = String::from_utf8(builder_fee_approval_advisory(
            Network::Testnet,
            builder,
            0,
            "x",
        ))
        .unwrap();
        assert!(revoke.contains("revokes"));

        let order = String::from_utf8(builder_order_advisory(builder, 10, 10100, false)).unwrap();
        assert!(order.contains(builder));
        assert!(order.contains("0.01%"));
        assert!(order.contains("0.0101 USDC"));

        let bound = String::from_utf8(session_builder_bound_advisory(builder, 25)).unwrap();
        assert!(bound.contains(builder));
        assert!(bound.contains("0.025%"));
        assert!(bound.contains("25 tenths of a basis point"));
    }

    #[test]
    fn withdrawal_claim_effects_bind_gross_debit_and_arbitrum_destination() {
        let destination =
            protocol::parse_address("0x00000000000000000000000000000000000000aa").unwrap();
        let effects = ClaimEffects::withdraw(5_000_000, destination);
        assert_eq!(
            effects.declared_debits,
            vec![json!({
                "asset": {"chain": "hyperliquid", "asset": "usdc"},
                "amount": "5000000",
            })]
        );
        assert_eq!(
            effects.declared_destinations,
            vec![json!({
                "chain": "arbitrum",
                "destination": "0x00000000000000000000000000000000000000aa",
            })]
        );
        // The Broker catalogues petal operation classes with a none fee asset,
        // so the claim must not declare a fee; the venue fee is disclosed in
        // the advisory and the operation record instead.
        assert_eq!(effects.declared_fee, json!({"kind": "none"}));
    }

    #[test]
    fn withdraw_request_rejects_zero_destination_and_fee_consumed_amounts() {
        let ok = Withdraw {
            destination: "0x00000000000000000000000000000000000000aa".into(),
            amount: "5".into(),
            nonce: None,
        };
        assert_eq!(validate_withdraw_request(&ok).unwrap().0, 5_000_000);

        let zero = Withdraw {
            destination: "0x0000000000000000000000000000000000000000".into(),
            amount: "5".into(),
            nonce: None,
        };
        assert_eq!(
            validate_withdraw_request(&zero).unwrap_err(),
            invalid("destination must be a non-zero external chain address")
        );

        for amount in ["1", "0.5", "1.000000"] {
            let consumed = Withdraw {
                destination: "0x00000000000000000000000000000000000000aa".into(),
                amount: amount.into(),
                nonce: None,
            };
            let error = validate_withdraw_request(&consumed).unwrap_err();
            assert!(
                format!("{error:?}").contains("exceed the venue withdrawal fee"),
                "{amount} must be rejected as fee-consumed"
            );
        }
    }

    #[test]
    fn withdraw_body_rejects_unknown_fields_and_malformed_shapes() {
        // A vault or session selector is not part of an owner withdrawal.
        assert!(serde_json::from_slice::<Withdraw>(
            br#"{"destination":"0x00000000000000000000000000000000000000aa","amount":"5","vault_address":"0x0000000000000000000000000000000000000001"}"#
        )
        .is_err());
        assert!(serde_json::from_slice::<Withdraw>(
            br#"{"destination":"0x00000000000000000000000000000000000000aa","amount":"5","key_ref":{}}"#
        )
        .is_err());
        assert!(serde_json::from_slice::<Withdraw>(br#"{"amount":"5"}"#).is_err());
        assert!(
            serde_json::from_slice::<Withdraw>(
                br#"{"destination":"0x00000000000000000000000000000000000000aa","amount":"0","nonce":null}"#
            )
            .is_err()
                || validate_withdraw_request(&serde_json::from_slice::<Withdraw>(
                    br#"{"destination":"0x00000000000000000000000000000000000000aa","amount":"0","nonce":null}"#
                )
                .unwrap())
                .is_err()
        );
    }

    #[test]
    fn micros_decimal_formats_canonically() {
        assert_eq!(micros_decimal(1_000_000), "1");
        assert_eq!(micros_decimal(4_000_000), "4");
        assert_eq!(micros_decimal(1_250_000), "1.25");
        assert_eq!(micros_decimal(1), "0.000001");
    }

    #[test]
    fn withdraw_advisory_discloses_fee_net_and_non_settlement() {
        let destination =
            protocol::parse_address("0x00000000000000000000000000000000000000aa").unwrap();
        let advisory = String::from_utf8(withdraw_advisory(5_000_000, destination)).unwrap();
        assert!(advisory.contains("Withdraws 5 USDC"));
        assert!(advisory.contains("0x00000000000000000000000000000000000000aa"));
        assert!(advisory.contains("Arbitrum"));
        assert!(advisory.contains("Venue fee: 1 USDC"));
        assert!(advisory.contains("Expected net receipt: 4 USDC"));
        assert!(advisory.contains("not settlement proof"));
    }

    #[test]
    fn withdrawal_is_outside_the_delegated_session_scope() {
        // The withdrawal route leaves sort after every session route, so its
        // ids must never appear in the derived-key scope; if a route file is
        // ever inserted ahead of them, this pins the authority boundary.
        assert!(
            SESSION_KEY_ALLOWED_ROUTES.iter().all(|id| *id < "r000049"),
            "session scope must stay below the withdrawal routes"
        );
        let expected = [
            "r000009", "r000010", "r000011", "r000014", "r000020", "r000024", "r000026",
        ];
        assert_eq!(SESSION_KEY_ALLOWED_ROUTES, expected);
    }

    #[test]
    fn withdraw_nonce_and_record_keys_are_isolated() {
        let wallet = "0x0000000000000000000000000000000000000001";
        let body = br#"{"destination":"0x00000000000000000000000000000000000000aa","amount":"5"}"#;
        assert_ne!(
            owner_nonce_key(Network::Mainnet, wallet, "withdraw.json", body),
            owner_nonce_key(Network::Mainnet, wallet, "send_asset.json", body)
        );
        assert_ne!(
            owner_nonce_key(Network::Mainnet, wallet, "withdraw.json", body),
            owner_nonce_key(Network::Testnet, wallet, "withdraw.json", body)
        );
        assert_eq!(
            withdraw_operation_key(Network::Mainnet, wallet, 42),
            "state/exchange/mainnet/0x0000000000000000000000000000000000000001/withdraw/42.json"
        );
        assert_eq!(
            withdraw_submitted_key(Network::Testnet, wallet, 42),
            "state/exchange/testnet/0x0000000000000000000000000000000000000001/withdraw/42.submitted.json"
        );
    }

    fn withdraw_intent(destination: &str, amount: &str, nonce: u64) -> WithdrawOperation {
        let dest = protocol::parse_address(destination).unwrap();
        let (action, payload) =
            protocol::withdraw_payload(Network::Mainnet, dest, amount, nonce).unwrap();
        WithdrawOperation {
            schema: "bloom.hyperliquid_withdraw.v1".into(),
            network: "mainnet".into(),
            wallet: "wallet".into(),
            destination: format!("{dest:#x}"),
            amount: amount.into(),
            amount_micros: "5000000".into(),
            fee_micros: "1000000".into(),
            nonce,
            action,
            payload_hash: hex::encode(payload.hash),
            status: "approval_pending".into(),
            response: None,
            updated_ms: 1,
        }
    }

    fn stored_like(intent: &WithdrawOperation, status: &str) -> WithdrawOperation {
        let mut stored = intent.clone();
        stored.status = status.into();
        stored
    }

    #[test]
    fn withdraw_resume_decision_table_covers_marker_and_status_combinations() {
        let intent = withdraw_intent("0x00000000000000000000000000000000000000aa", "5", 42);
        for marker in [false, true] {
            // No record: proceed (a marker without a submitted/accepted record
            // can only come from an attempt that died before its POST).
            assert_eq!(
                withdraw_resume(&intent, None, marker),
                Ok(WithdrawResume::Proceed {
                    stale_marker: marker,
                    record: None,
                })
            );
            // Terminal and uncertain states are decided regardless of marker.
            assert_eq!(
                withdraw_resume(&intent, Some(stored_like(&intent, "accepted")), marker),
                Ok(WithdrawResume::Completed)
            );
            assert_eq!(
                withdraw_resume(&intent, Some(stored_like(&intent, "submitted")), marker),
                Err(WithdrawRefusal::Uncertain)
            );
            // Pre-submission states proceed; the marker is stale exactly when
            // it exists.
            for status in ["approval_pending", "rejected"] {
                assert_eq!(
                    withdraw_resume(&intent, Some(stored_like(&intent, status)), marker),
                    Ok(WithdrawResume::Proceed {
                        stale_marker: marker,
                        record: Some(Box::new(stored_like(&intent, status))),
                    })
                );
            }
            // A corrupted status refuses instead of guessing.
            assert!(matches!(
                withdraw_resume(&intent, Some(stored_like(&intent, "weird")), marker),
                Err(WithdrawRefusal::Unrecognized(_))
            ));
        }
    }

    #[test]
    fn withdraw_resume_rejects_nonce_reuse_across_different_intents() {
        // A stored record for destination ..aa must never answer, sign, or
        // complete a request for destination ..bb at the same nonce — no
        // matter which status the old record carries.
        let intent = withdraw_intent("0x00000000000000000000000000000000000000bb", "5", 42);
        for status in ["approval_pending", "submitted", "accepted", "rejected"] {
            let stored = withdraw_intent("0x00000000000000000000000000000000000000aa", "5", 42);
            let mut stored = stored_like(&stored, status);
            // Exercise both identity fields independently.
            if status == "accepted" {
                stored.payload_hash = "0".repeat(64);
            }
            assert_eq!(
                withdraw_resume(&intent, Some(stored), false),
                Err(WithdrawRefusal::IdentityMismatch)
            );
        }
        // Same intent is never a mismatch (covered by the table test) — and a
        // changed amount is a different intent, not a retry.
        let other_amount = withdraw_intent("0x00000000000000000000000000000000000000bb", "6", 42);
        let stored = stored_like(&other_amount, "accepted");
        let intent = withdraw_intent("0x00000000000000000000000000000000000000bb", "5", 42);
        assert_eq!(
            withdraw_resume(&intent, Some(stored), true),
            Err(WithdrawRefusal::IdentityMismatch)
        );
    }

    #[test]
    fn withdraw_record_names_filter_markers_and_sort_numerically() {
        let prefix = "state/exchange/mainnet/w/withdraw";
        let keys = [
            format!("{prefix}/42.json"),
            format!("{prefix}/7.submitted.json"),
            format!("{prefix}/7.json"),
            format!("{prefix}/100.json"),
            format!("{prefix}/junk.json"),
            format!("{prefix}/nested/9.json"),
            format!("{prefix}/1042.json"),
        ];
        assert_eq!(
            withdraw_record_names(prefix, &keys),
            vec![
                "7.json".to_string(),
                "42.json".to_string(),
                "100.json".to_string(),
                "1042.json".to_string(),
            ]
        );
    }

    #[test]
    fn delegated_sessions_reject_vault_and_spot_targets() {
        let request = SignSubmit {
            action: ExchangeAction::ScheduleCancel { time: Some(123) },
            nonce: None,
            vault_address: Some("0x0000000000000000000000000000000000000001".into()),
            expires_after: None,
        };
        assert!(
            validate_session_target(&request)
                .unwrap_err()
                .contains("vault")
        );

        let mut unrestricted = bounded_session();
        unrestricted.assets.clear();
        let spot = ExchangeAction::Cancel {
            cancels: vec![protocol::CancelWire {
                asset: 10_000,
                oid: 42,
            }],
            fast: None,
        };
        assert_eq!(
            session_policy(&unrestricted, &spot),
            Err("delegated sessions do not support spot asset ids".into())
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
    fn session_policy_enforces_the_session_builder_bound() {
        let mut session = bounded_session();
        let order = order_action_with_builder("0x0000000000000000000000000000000000000001", 10);

        // no builder bound configured on the session: rejected outright
        assert_eq!(
            session_policy(&session, &order),
            Err("builder fee is outside the session's approved builder bound".into())
        );

        session.builder_address = Some("0x0000000000000000000000000000000000000001".into());
        session.max_builder_fee_tenths_bps = Some(10);
        // matching address, fee at the session cap: accepted
        assert_eq!(session_policy(&session, &order), Ok(()));

        // fee above the session's cap (but within the venue cap): rejected
        let over_cap = order_action_with_builder("0x0000000000000000000000000000000000000001", 11);
        assert_eq!(
            session_policy(&session, &over_cap),
            Err("builder fee is outside the session's approved builder bound".into())
        );

        // a different builder address: rejected even though the fee is in range
        let other_builder =
            order_action_with_builder("0x0000000000000000000000000000000000000002", 5);
        assert_eq!(
            session_policy(&session, &other_builder),
            Err("builder fee is outside the session's approved builder bound".into())
        );

        // an order without a builder is unaffected by the bound
        let plain_order: ExchangeAction = serde_json::from_value(json!({
            "type": "order",
            "orders": [{
                "a": 0, "b": true, "p": "100", "s": "0.01", "r": false,
                "t": {"limit": {"tif": "Gtc"}}
            }],
            "grouping": "na"
        }))
        .unwrap();
        assert_eq!(session_policy(&session, &plain_order), Ok(()));
    }

    #[test]
    fn session_preflight_enforces_builder_bound_pairing_case_and_cap() {
        fn request(
            builder_address: Option<&str>,
            max_builder_fee_tenths_bps: Option<u32>,
        ) -> NewSession {
            NewSession {
                id: "session".into(),
                duration_ms: None,
                agent_name: None,
                max_notional_usd: None,
                max_leverage: None,
                assets: Vec::new(),
                builder_address: builder_address.map(str::to_owned),
                max_builder_fee_tenths_bps,
                nonce: None,
            }
        }

        // neither field set: fine, no builder bound
        assert!(session_preflight(&request(None, None)).is_ok());

        // set together, within the perp venue cap: fine
        assert!(
            session_preflight(&request(
                Some("0x0000000000000000000000000000000000000001"),
                Some(100)
            ))
            .is_ok()
        );

        // only one of the pair set: rejected
        assert_eq!(
            session_preflight(&request(
                Some("0x0000000000000000000000000000000000000001"),
                None
            )),
            Err("builder_address and max_builder_fee_tenths_bps must be set together".into())
        );
        assert_eq!(
            session_preflight(&request(None, Some(10))),
            Err("builder_address and max_builder_fee_tenths_bps must be set together".into())
        );

        // uppercase address: rejected (the "0x" prefix must stay intact)
        let checksummed = format!(
            "0x{}",
            "000000000000000000000000000000000000000a".to_ascii_uppercase()
        );
        assert_eq!(
            session_preflight(&request(Some(checksummed.as_str()), Some(10))),
            Err("builder_address must be lowercase".into())
        );

        // above the perp venue cap (sessions never submit spot orders): rejected
        assert_eq!(
            session_preflight(&request(
                Some("0x0000000000000000000000000000000000000001"),
                Some(101)
            )),
            Err("max_builder_fee_tenths_bps must be 1..=100".into())
        );

        // zero: rejected
        assert_eq!(
            session_preflight(&request(
                Some("0x0000000000000000000000000000000000000001"),
                Some(0)
            )),
            Err("max_builder_fee_tenths_bps must be 1..=100".into())
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

    #[test]
    fn correlated_receipts_are_action_and_cloid_scoped() {
        let order: ExchangeAction = serde_json::from_value(json!({
            "type": "order",
            "orders": [
                {
                    "a": 0,
                    "b": false,
                    "p": "101",
                    "s": "0.1",
                    "r": false,
                    "t": {"limit": {"tif": "Ioc"}}
                },
                {
                    "a": 0,
                    "b": true,
                    "p": "100",
                    "s": "0.1",
                    "r": false,
                    "t": {"limit": {"tif": "Alo"}},
                    "c": "0xAABBCCDDEEFF00112233445566778899"
                }
            ],
            "grouping": "na"
        }))
        .unwrap();
        assert_eq!(receipt_action(&order), Some("order"));
        assert_eq!(receipt_item_count(&order), 2);
        let targets = receipt_targets(&order).unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].item_index, 1);
        assert_eq!(targets[0].cloid, "0xaabbccddeeff00112233445566778899");
        assert_eq!(
            targets[0].request["c"],
            "0xAABBCCDDEEFF00112233445566778899"
        );
        assert_eq!(
            session_receipt_key(
                Network::Mainnet,
                "wallet",
                "session",
                "0xAABBCCDDEEFF00112233445566778899",
                "order"
            ),
            "state/sessions/mainnet/wallet/session/receipts/0xaabbccddeeff00112233445566778899/order.json"
        );

        let cancel: ExchangeAction = serde_json::from_value(json!({
            "type": "cancelByCloid",
            "cancels": [{
                "asset": 0,
                "cloid": "0xAABBCCDDEEFF00112233445566778899"
            }]
        }))
        .unwrap();
        assert_eq!(receipt_action(&cancel), Some("cancel"));
        assert_eq!(receipt_item_count(&cancel), 1);
        let cancel_targets = receipt_targets(&cancel).unwrap();
        assert_eq!(cancel_targets[0].item_index, 0);
        assert_eq!(cancel_targets[0].cloid, targets[0].cloid);
    }

    #[test]
    fn correlated_response_contains_only_the_target_items_status() {
        let response = json!({
            "status": "ok",
            "response": {
                "type": "order",
                "data": {
                    "statuses": [
                        {"filled": {"oid": 11, "totalSz": "0.1", "avgPx": "101"}},
                        {"resting": {"oid": 22}}
                    ]
                }
            }
        });
        let targets = [ReceiptTarget {
            item_index: 1,
            cloid: "0xaabbccddeeff00112233445566778899".into(),
            request: json!({"c": "0xAABBCCDDEEFF00112233445566778899"}),
        }];
        let statuses = response
            .pointer("/response/data/statuses")
            .and_then(Value::as_array)
            .unwrap();
        let mut correlated = response.clone();
        *correlated.pointer_mut("/response/data/statuses").unwrap() =
            Value::Array(vec![statuses[targets[0].item_index].clone()]);
        assert_eq!(
            correlated.pointer("/response/data/statuses"),
            Some(&json!([{"resting": {"oid": 22}}]))
        );
    }

    #[test]
    fn receipt_reservations_bind_the_full_operation_and_match_final_receipts() {
        let targets = [ReceiptTarget {
            item_index: 1,
            cloid: "0xaabbccddeeff00112233445566778899".into(),
            request: json!({"c": "0xAABBCCDDEEFF00112233445566778899"}),
        }];
        let batch = ReceiptBatch {
            action: "order",
            item_count: 2,
            targets: &targets,
        };
        let reservations = receipt_reservations(123, "operation-digest", &batch);
        assert_eq!(reservations.len(), 1);
        assert_eq!(reservations[0].operation_digest, "operation-digest");
        assert!(receipt_matches_reservation(
            &json!({
                "action": "order",
                "cloid": "0xaabbccddeeff00112233445566778899",
                "nonce": 123,
                "item_index": 1,
                "request": {"c": "0xAABBCCDDEEFF00112233445566778899"},
                "response": {"status": "ok"}
            }),
            &reservations[0]
        ));
        assert!(!receipt_matches_reservation(
            &json!({
                "action": "order",
                "cloid": "0xaabbccddeeff00112233445566778899",
                "nonce": 124,
                "item_index": 1,
                "request": {"c": "0xAABBCCDDEEFF00112233445566778899"}
            }),
            &reservations[0]
        ));
        assert_eq!(
            session_receipt_reservation_key(
                Network::Mainnet,
                "wallet",
                "session",
                "0xAABBCCDDEEFF00112233445566778899",
                "order"
            ),
            "state/sessions/mainnet/wallet/session/receipt_reservations/0xaabbccddeeff00112233445566778899/order.json"
        );
    }
}
