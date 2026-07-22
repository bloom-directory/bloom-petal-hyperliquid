use alloy::primitives::{Address, B256, Signature};
use alloy_dyn_abi::eip712::TypedData;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha3::{Digest, Keccak256};

pub const MAINNET_URL: &str = "https://api.hyperliquid.xyz";
pub const TESTNET_URL: &str = "https://api.hyperliquid-testnet.xyz";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
}
impl Network {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "mainnet" => Ok(Self::Mainnet),
            "testnet" => Ok(Self::Testnet),
            _ => Err(format!("unsupported network {raw}")),
        }
    }
    pub fn url(self) -> &'static str {
        match self {
            Self::Mainnet => MAINNET_URL,
            Self::Testnet => TESTNET_URL,
        }
    }
    pub fn chain(self) -> &'static str {
        match self {
            Self::Mainnet => "Mainnet",
            Self::Testnet => "Testnet",
        }
    }
    pub fn source(self) -> &'static str {
        match self {
            Self::Mainnet => "a",
            Self::Testnet => "b",
        }
    }
    pub fn signature_chain_id(self) -> u64 {
        match self {
            Self::Mainnet => 0xa4b1,
            Self::Testnet => 0x66eee,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureJson {
    pub r: String,
    pub s: String,
    pub v: u8,
}
impl SignatureJson {
    pub fn from_raw(raw: &[u8]) -> Result<Self, String> {
        let sig = Signature::from_raw(raw).map_err(|e| format!("invalid signature: {e}"))?;
        let b = sig.as_bytes();
        let mut v = b[64];
        if v < 27 {
            v += 27;
        }
        Ok(Self {
            r: format!("0x{}", hex::encode(&b[..32])),
            s: format!("0x{}", hex::encode(&b[32..64])),
            v,
        })
    }

    pub fn validate(&self) -> Result<(), String> {
        fn part(name: &str, value: &str) -> Result<(), String> {
            if value.len() != 66
                || !value.starts_with("0x")
                || !value[2..].bytes().all(|b| b.is_ascii_hexdigit())
            {
                return Err(format!("signature {name} must be a 32-byte 0x hex string"));
            }
            Ok(())
        }
        part("r", &self.r)?;
        part("s", &self.s)?;
        if !matches!(self.v, 27 | 28) {
            return Err("signature v must be 27 or 28".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ExchangeAction {
    #[serde(rename = "order")]
    Order {
        orders: Vec<OrderWire>,
        grouping: Grouping,
        #[serde(skip_serializing_if = "Option::is_none")]
        builder: Option<BuilderFee>,
    },
    #[serde(rename = "cancel")]
    Cancel {
        cancels: Vec<CancelWire>,
        #[serde(rename = "f", skip_serializing_if = "Option::is_none")]
        fast: Option<bool>,
    },
    #[serde(rename = "cancelByCloid")]
    CancelByCloid {
        cancels: Vec<CancelByCloidWire>,
        #[serde(rename = "f", skip_serializing_if = "Option::is_none")]
        fast: Option<bool>,
    },
    #[serde(rename = "scheduleCancel")]
    ScheduleCancel {
        #[serde(skip_serializing_if = "Option::is_none")]
        time: Option<u64>,
    },
    #[serde(rename = "updateLeverage")]
    UpdateLeverage {
        asset: u32,
        #[serde(rename = "isCross")]
        is_cross: bool,
        leverage: u32,
    },
}
impl ExchangeAction {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Order { .. } => "order",
            Self::Cancel { .. } => "cancel",
            Self::CancelByCloid { .. } => "cancelByCloid",
            Self::ScheduleCancel { .. } => "scheduleCancel",
            Self::UpdateLeverage { .. } => "updateLeverage",
        }
    }
    pub fn intent(&self) -> &'static str {
        match self {
            Self::Order { .. } => "hyperliquid.order",
            Self::Cancel { .. } => "hyperliquid.cancel",
            Self::CancelByCloid { .. } => "hyperliquid.cancel_by_cloid",
            Self::ScheduleCancel { .. } => "hyperliquid.schedule_cancel",
            Self::UpdateLeverage { .. } => "hyperliquid.update_leverage",
        }
    }
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Order { orders, .. } => {
                if orders.is_empty() {
                    return Err("orders must not be empty".into());
                }
                for o in orders {
                    o.validate()?;
                }
            }
            Self::Cancel { cancels, fast } => {
                if cancels.is_empty() {
                    return Err("cancels must not be empty".into());
                };
                if *fast == Some(false) {
                    return Err("omit f when false".into());
                }
            }
            Self::CancelByCloid { cancels, fast } => {
                if cancels.is_empty() {
                    return Err("cancels must not be empty".into());
                };
                if *fast == Some(false) {
                    return Err("omit f when false".into());
                };
                for c in cancels {
                    cloid(&c.cloid)?;
                }
            }
            Self::ScheduleCancel { .. } => {}
            Self::UpdateLeverage { leverage, .. } => {
                if *leverage == 0 || *leverage > 50 {
                    return Err("leverage must be 1..=50".into());
                }
            }
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderWire {
    #[serde(rename = "a")]
    pub asset: u32,
    #[serde(rename = "b")]
    pub is_buy: bool,
    #[serde(rename = "p")]
    pub price: String,
    #[serde(rename = "s")]
    pub size: String,
    #[serde(rename = "r")]
    pub reduce_only: bool,
    #[serde(rename = "t")]
    pub order_type: OrderTypeWire,
    #[serde(rename = "c", skip_serializing_if = "Option::is_none")]
    pub cloid: Option<String>,
}
impl OrderWire {
    fn validate(&self) -> Result<(), String> {
        decimal("price", &self.price)?;
        decimal("size", &self.size)?;
        if let Some(c) = &self.cloid {
            cloid(c)?;
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Grouping {
    #[serde(rename = "na")]
    Na,
    #[serde(rename = "normalTpsl")]
    NormalTpsl,
    #[serde(rename = "positionTpsl")]
    PositionTpsl,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuilderFee {
    #[serde(rename = "b")]
    pub address: String,
    #[serde(rename = "f")]
    pub fee_tenths_bps: u32,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderTypeWire {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<LimitOrderType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trigger: Option<TriggerOrderType>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitOrderType {
    pub tif: TimeInForce,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggerOrderType {
    #[serde(rename = "isMarket")]
    pub is_market: bool,
    #[serde(rename = "triggerPx")]
    pub trigger_px: String,
    pub tpsl: TpSl,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum TimeInForce {
    #[serde(rename = "Alo")]
    Alo,
    #[serde(rename = "Ioc")]
    Ioc,
    #[serde(rename = "Gtc")]
    Gtc,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TpSl {
    Tp,
    Sl,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancelWire {
    #[serde(rename = "a")]
    pub asset: u32,
    #[serde(rename = "o")]
    pub oid: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancelByCloidWire {
    pub asset: u32,
    pub cloid: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SignSubmit {
    pub action: ExchangeAction,
    #[serde(default)]
    pub nonce: Option<u64>,
    #[serde(default, rename = "vaultAddress")]
    pub vault_address: Option<String>,
    #[serde(default, rename = "expiresAfter")]
    pub expires_after: Option<u64>,
}
#[derive(Debug, Clone, Deserialize)]
pub struct SignedSubmit {
    pub action: ExchangeAction,
    pub nonce: u64,
    pub signature: SignatureJson,
    #[serde(default, rename = "vaultAddress")]
    pub vault_address: Option<String>,
    #[serde(default, rename = "expiresAfter")]
    pub expires_after: Option<u64>,
}

pub fn parse_address(raw: &str) -> Result<Address, String> {
    if raw.len() != 42 || !raw.starts_with("0x") || !raw[2..].chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err("address must be a 42-character 0x hex string".into());
    };
    raw.parse().map_err(|e| format!("address: {e}"))
}
fn cloid(raw: &str) -> Result<(), String> {
    if raw.len() != 34 || !raw.starts_with("0x") || !raw[2..].chars().all(|c| c.is_ascii_hexdigit())
    {
        Err("cloid must be a 34-character 0x hex string".into())
    } else {
        Ok(())
    }
}
fn decimal(name: &str, raw: &str) -> Result<(), String> {
    if raw.is_empty()
        || raw.len() > 40
        || raw.starts_with('-')
        || raw.starts_with('+')
        || raw.contains('e')
        || raw.contains('E')
        || raw.starts_with('.')
        || raw.ends_with('.')
        || raw.contains("..")
        || raw.ends_with('0') && raw.contains('.')
        || !raw.chars().all(|c| c.is_ascii_digit() || c == '.')
    {
        Err(format!("{name} must be a canonical decimal"))
    } else {
        let value = raw
            .parse::<f64>()
            .map_err(|_| format!("{name} is not a decimal"))?;
        if !value.is_finite() || value <= 0.0 {
            return Err(format!("{name} must be > 0"));
        }
        Ok(())
    }
}

pub fn action_hash(
    action: &ExchangeAction,
    nonce: u64,
    vault: Option<Address>,
    expires: Option<u64>,
) -> Result<B256, String> {
    let mut bytes = rmp_serde::to_vec_named(action).map_err(|e| e.to_string())?;
    bytes.extend_from_slice(&nonce.to_be_bytes());
    match vault {
        Some(a) => {
            bytes.push(1);
            bytes.extend_from_slice(a.as_slice())
        }
        None => bytes.push(0),
    }
    if let Some(e) = expires {
        bytes.push(0);
        bytes.extend_from_slice(&e.to_be_bytes())
    }
    Ok(B256::from_slice(&Keccak256::digest(bytes)))
}
fn typed_agent(network: Network, connection: B256) -> Result<TypedData, String> {
    serde_json::from_value(json!({"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Agent":[{"name":"source","type":"string"},{"name":"connectionId","type":"bytes32"}]},"primaryType":"Agent","domain":{"name":"Exchange","version":"1","chainId":1337,"verifyingContract":"0x0000000000000000000000000000000000000000"},"message":{"source":network.source(),"connectionId":format!("{connection:#x}")}})).map_err(|e|e.to_string())
}
pub fn l1_signing_hash(
    network: Network,
    action: &ExchangeAction,
    nonce: u64,
    vault: Option<Address>,
    expires: Option<u64>,
) -> Result<B256, String> {
    let td = typed_agent(network, action_hash(action, nonce, vault, expires)?)?;
    let hash: B256 = td.eip712_signing_hash().map_err(|e| e.to_string())?;
    Ok(hash)
}
fn user_typed(network: Network, kind: &str, message: Value) -> Result<TypedData, String> {
    let type_fields = match kind {
        "approveAgent" => {
            json!([{"name":"hyperliquidChain","type":"string"},{"name":"agentAddress","type":"address"},{"name":"agentName","type":"string"},{"name":"nonce","type":"uint64"}])
        }
        "usdSend" => {
            json!([{"name":"hyperliquidChain","type":"string"},{"name":"destination","type":"string"},{"name":"amount","type":"string"},{"name":"time","type":"uint64"}])
        }
        _ => return Err("unsupported user action".into()),
    };
    serde_json::from_value(json!({"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],format!("HyperliquidTransaction:{kind}"):type_fields},"primaryType":format!("HyperliquidTransaction:{kind}"),"domain":{"name":"HyperliquidSignTransaction","version":"1","chainId":network.signature_chain_id(),"verifyingContract":"0x0000000000000000000000000000000000000000"},"message":message})).map_err(|e|e.to_string())
}
pub fn approve_agent_hash(
    network: Network,
    agent: Address,
    name: &str,
    nonce: u64,
) -> Result<(Value, B256), String> {
    let msg = json!({"hyperliquidChain":network.chain(),"agentAddress":format!("{agent:#x}"),"agentName":name,"nonce":nonce});
    let td = user_typed(network, "approveAgent", msg)?;
    let hash: B256 = td.eip712_signing_hash().map_err(|e| e.to_string())?;
    Ok((
        json!({"type":"approveAgent","hyperliquidChain":network.chain(),"signatureChainId":format!("0x{:x}",network.signature_chain_id()),"agentAddress":format!("{agent:#x}"),"agentName":name,"nonce":nonce}),
        hash,
    ))
}
pub fn usd_send_hash(
    network: Network,
    destination: Address,
    amount: &str,
    nonce: u64,
) -> Result<(Value, B256), String> {
    let msg = json!({"hyperliquidChain":network.chain(),"destination":format!("{destination:#x}"),"amount":amount,"time":nonce});
    let td = user_typed(network, "usdSend", msg)?;
    let hash: B256 = td.eip712_signing_hash().map_err(|e| e.to_string())?;
    Ok((
        json!({"type":"usdSend","hyperliquidChain":network.chain(),"signatureChainId":format!("0x{:x}",network.signature_chain_id()),"destination":format!("{destination:#x}"),"amount":amount,"time":nonce}),
        hash,
    ))
}
pub fn user_payload(action: Value, nonce: u64, sig: SignatureJson) -> Value {
    json!({"action":action,"nonce":nonce,"signature":sig})
}
pub fn exchange_payload(
    action: ExchangeAction,
    nonce: u64,
    sig: SignatureJson,
    vault: Option<String>,
    expires: Option<u64>,
) -> Result<Value, String> {
    action.validate()?;
    sig.validate()?;
    let mut v = json!({"action":action,"nonce":nonce,"signature":sig});
    let o = v.as_object_mut().unwrap();
    if let Some(x) = vault {
        parse_address(&x)?;
        o.insert("vaultAddress".into(), Value::String(x.to_ascii_lowercase()));
    }
    if let Some(x) = expires {
        o.insert("expiresAfter".into(), Value::from(x));
    }
    Ok(v)
}

pub fn validate_usdc_amount(raw: &str) -> Result<(), String> {
    if raw.is_empty()
        || raw.len() > 40
        || raw.starts_with('-')
        || raw.starts_with('+')
        || raw.contains('e')
        || raw.contains('E')
    {
        return Err("amount must be a plain positive USDC decimal".into());
    }
    let mut pieces = raw.split('.');
    let whole = pieces.next().unwrap_or_default();
    let fraction = pieces.next().unwrap_or_default();
    if pieces.next().is_some()
        || whole.is_empty()
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || !fraction.bytes().all(|b| b.is_ascii_digit())
        || fraction.len() > 6
    {
        return Err("amount must have at most 6 decimal places".into());
    }
    let micros = whole
        .parse::<u64>()
        .map_err(|_| "amount is too large".to_string())?
        .checked_mul(1_000_000)
        .and_then(|x| {
            let mut padded = fraction.to_string();
            while padded.len() < 6 {
                padded.push('0');
            }
            padded.parse::<u64>().ok().and_then(|f| x.checked_add(f))
        })
        .ok_or_else(|| "amount is too large".to_string())?;
    if micros == 0 {
        return Err("amount must be greater than zero".into());
    }
    Ok(())
}

pub fn validate_exchange_response(value: &Value) -> Result<(), String> {
    if value.get("status").and_then(Value::as_str) != Some("ok") {
        return Err(format!("Hyperliquid exchange rejected action: {value}"));
    }
    if let Some(statuses) = value
        .pointer("/response/data/statuses")
        .and_then(Value::as_array)
    {
        for status in statuses {
            if let Some(error) = status.get("error").and_then(Value::as_str) {
                return Err(format!("Hyperliquid exchange rejected action: {error}"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cancel() -> ExchangeAction {
        ExchangeAction::Cancel {
            cancels: vec![CancelWire { asset: 0, oid: 42 }],
            fast: None,
        }
    }

    #[test]
    fn exchange_hash_is_stable_and_network_independent() {
        let a = cancel();
        let one = l1_signing_hash(Network::Mainnet, &a, 123, None, None).unwrap();
        let two = l1_signing_hash(Network::Mainnet, &a, 123, None, None).unwrap();
        assert_eq!(one, two);
        assert_ne!(
            one,
            l1_signing_hash(Network::Testnet, &a, 123, None, None).unwrap()
        );
    }

    #[test]
    fn payload_rejects_empty_cancel_and_invalid_addresses() {
        let empty = ExchangeAction::Cancel {
            cancels: vec![],
            fast: None,
        };
        let sig = SignatureJson {
            r: format!("0x{}", "00".repeat(32)),
            s: format!("0x{}", "00".repeat(32)),
            v: 27,
        };
        assert!(exchange_payload(empty, 1, sig.clone(), None, None).is_err());
        assert!(parse_address("0x1234").is_err());
        assert!(exchange_payload(cancel(), 1, sig, Some("0x1234".into()), None).is_err());
    }

    #[test]
    fn user_hash_contains_correct_wire_action() {
        let destination = parse_address("0x0000000000000000000000000000000000000001").unwrap();
        let (action, hash) = usd_send_hash(Network::Testnet, destination, "1.25", 99).unwrap();
        assert_eq!(action["type"], "usdSend");
        assert_eq!(action["time"], 99);
        assert_ne!(hash, B256::ZERO);
    }

    #[test]
    fn rejects_malformed_signatures_and_amounts() {
        assert!(
            SignatureJson {
                r: "0x00".into(),
                s: "0x00".into(),
                v: 27
            }
            .validate()
            .is_err()
        );
        assert!(
            SignatureJson {
                r: format!("0x{}", "00".repeat(32)),
                s: format!("0x{}", "00".repeat(32)),
                v: 0
            }
            .validate()
            .is_err()
        );
        assert!(validate_usdc_amount("0").is_err());
        assert!(validate_usdc_amount("1.0000001").is_err());
        assert!(validate_usdc_amount("1.25").is_ok());
    }

    #[test]
    fn rejects_exchange_error_envelopes() {
        assert!(validate_exchange_response(&json!({"status":"err","response":"bad"})).is_err());
        assert!(
            validate_exchange_response(&json!({
                "status":"ok",
                "response":{"data":{"statuses":[{"error":"bad order"}]}}
            }))
            .is_err()
        );
        assert!(validate_exchange_response(&json!({"status":"ok"})).is_ok());
    }
}
