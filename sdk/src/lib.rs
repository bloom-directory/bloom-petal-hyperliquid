#![allow(clippy::crate_in_macro_def, clippy::too_many_arguments)]

pub mod bindings {
    wit_bindgen::generate!({
        path: "wit",
        world: "route-file",
        pub_export_macro: true,
        default_bindings_module: "petal::bindings",
        with: {
            "bloom:http/fetch@0.1.0": generate,
            "bloom:store/kv@0.1.0": generate,
            "bloom:sign/signing@0.1.0": generate,
            "bloom:tx/outbox@0.1.0": generate,
            "bloom:vfs/readwrite@0.1.0": generate,
            "bloom:env/runtime@0.1.0": generate,
        }
    });
}

fn component_getrandom(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    let bytes = sdk::random_bytes(buf.len()).map_err(|_| getrandom::Error::UNSUPPORTED)?;
    buf.copy_from_slice(&bytes);
    Ok(())
}
getrandom::register_custom_getrandom!(component_getrandom);

pub use bindings::bloom::route::types::EntryKind;
pub use bindings::{Ctx as RawCtx, Entry, Guest as RawGuest, RouteError, RouteMeta};

pub trait RouteIdentity {
    const PATH: &'static str;
    const CANONICAL_PATH: &'static str;
    const PARAMS: &'static [(&'static str, usize)];
}

#[derive(Clone, Debug)]
pub struct Ctx {
    pub petal_root: String,
    pub package_hash: String,
    pub path: String,
    pub params: Vec<(String, String)>,
    pub actor: Option<String>,
    identity_path: &'static str,
    identity_params: &'static [(&'static str, usize)],
}
impl Ctx {
    pub fn bind<I: RouteIdentity>(raw: RawCtx) -> Self {
        Self {
            petal_root: raw.petal_root,
            package_hash: raw.package_hash,
            path: raw.path,
            params: raw.params,
            actor: raw.actor,
            identity_path: I::PATH,
            identity_params: I::PARAMS,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DispatchResponse {
    Read(Vec<u8>),
    Write,
    Error { code: i32, message: String },
}

pub fn error(code: i32, message: impl Into<String>) -> DispatchResponse {
    DispatchResponse::Error {
        code,
        message: message.into(),
    }
}
pub fn route_error(code: i32, msg: String) -> RouteError {
    match code {
        -1 => RouteError::NotFound(msg),
        -2 => RouteError::Denied(msg),
        -3 => RouteError::Invalid(msg),
        -4 => RouteError::Backend(msg),
        _ => RouteError::Unsupported(msg),
    }
}
pub fn framework_read(r: DispatchResponse) -> Result<Vec<u8>, RouteError> {
    match r {
        DispatchResponse::Read(v) => Ok(v),
        DispatchResponse::Error { code, message } => Err(route_error(code, message)),
        _ => Err(RouteError::Backend("not a read response".into())),
    }
}
pub fn framework_write(r: DispatchResponse) -> Result<(), RouteError> {
    match r {
        DispatchResponse::Write => Ok(()),
        DispatchResponse::Error { code, message } => Err(route_error(code, message)),
        _ => Err(RouteError::Backend("not a write response".into())),
    }
}
pub fn param<'a>(ctx: &'a Ctx, name: &str) -> Result<&'a str, DispatchResponse> {
    if let Some((_, v)) = ctx.params.iter().find(|(k, _)| k == name) {
        return Ok(v);
    }
    for (candidate, index) in ctx.identity_params {
        if *candidate == name
            && let Some(v) = ctx.path.split('/').nth(*index)
        {
            return Ok(v);
        }
    }
    Err(error(-3, format!("missing {name}")))
}
pub fn current_route_path(ctx: &Ctx) -> &'static str {
    ctx.identity_path
}
pub fn read_json<T: serde::Serialize>(v: &T) -> DispatchResponse {
    serde_json::to_vec_pretty(v)
        .map(DispatchResponse::Read)
        .unwrap_or_else(|e| error(-4, e.to_string()))
}

#[derive(Clone, Copy)]
pub enum Kind {
    Dir,
    File,
    Writable,
}
#[derive(Clone, Copy)]
pub struct Spec {
    pub kind: Kind,
    pub caps: &'static [&'static str],
    pub ttl: Option<u64>,
    pub side_effecting: bool,
}
impl Spec {
    pub const fn caps(mut self, caps: &'static [&'static str]) -> Self {
        self.caps = caps;
        self
    }
}
pub const NONE: &[&str] = &[];
pub const READ: &[&str] = &["bloom:http", "bloom:store"];
pub const WRITE: &[&str] = &["bloom:http", "bloom:store", "bloom:sign"];
pub const HTTP: &[&str] = &["bloom:http"];
pub const STORE: &[&str] = &["bloom:store"];
pub const DIR: &[&str] = &["bloom:store", "bloom:vfs.read"];
pub fn dir_spec() -> Spec {
    Spec {
        kind: Kind::Dir,
        caps: NONE,
        ttl: Some(30_000),
        side_effecting: false,
    }
}
pub fn http_dir_spec() -> Spec {
    Spec {
        kind: Kind::Dir,
        caps: HTTP,
        ttl: Some(30_000),
        side_effecting: false,
    }
}
pub fn read_spec() -> Spec {
    Spec {
        kind: Kind::File,
        caps: NONE,
        ttl: Some(30_000),
        side_effecting: false,
    }
}
pub fn http_read_spec() -> Spec {
    Spec {
        kind: Kind::File,
        caps: HTTP,
        ttl: Some(5_000),
        side_effecting: true,
    }
}
pub fn store_read_spec() -> Spec {
    Spec {
        kind: Kind::File,
        caps: STORE,
        ttl: Some(30_000),
        side_effecting: false,
    }
}
pub fn account_read_spec() -> Spec {
    Spec {
        kind: Kind::File,
        caps: READ,
        ttl: Some(5_000),
        side_effecting: true,
    }
}
pub fn write_spec() -> Spec {
    Spec {
        kind: Kind::Writable,
        caps: WRITE,
        ttl: None,
        side_effecting: true,
    }
}

pub fn petal_entry(ctx: &Ctx, spec: Spec) -> Entry {
    let name = ctx
        .path
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("");
    Entry {
        name: name.into(),
        kind: match spec.kind {
            Kind::Dir => EntryKind::Dir,
            _ => EntryKind::File,
        },
        mode: match spec.kind {
            Kind::Dir => 0o755,
            Kind::File => 0o444,
            Kind::Writable => 0o644,
        },
        size: Some(0),
        link_target: None,
    }
}
pub fn metadata(ctx: &Ctx, spec: Spec) -> Result<RouteMeta, RouteError> {
    Ok(RouteMeta {
        kind: match spec.kind {
            Kind::Dir => EntryKind::Dir,
            _ => EntryKind::File,
        },
        mode: match spec.kind {
            Kind::Dir => 0o755,
            Kind::File => 0o444,
            Kind::Writable => 0o644,
        },
        cache_ttl_ms: spec.ttl,
        side_effecting_read: spec.side_effecting,
        write_async: false,
        description: Some(format!("Hyperliquid route {}", ctx.identity_path)),
        consent_summary: None,
        required_caps: spec.caps.iter().map(|s| (*s).to_string()).collect(),
        sign_intent: None,
        executable: false,
    })
}

pub mod sdk {
    use super::{DispatchResponse, error};
    use crate::bindings::bloom::{
        env::runtime as env, http::fetch as http, sign::signing as sign, store::kv as store,
        tx::outbox as tx, vfs::readwrite as vfs,
    };
    pub fn now_ms() -> u64 {
        env::now_ms().unwrap_or(0)
    }
    pub fn random_bytes(n: usize) -> Result<Vec<u8>, String> {
        env::random_bytes(u32::try_from(n).map_err(|_| "length too large")?)
    }
    pub fn http(
        method: &str,
        url: &str,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) -> Result<(u16, Vec<u8>), String> {
        let r = http::fetch(&http::Request {
            method: method.into(),
            url: url.into(),
            headers,
            body,
        })?;
        Ok((r.status, r.body))
    }
    fn ns(key: &str) -> (&'static str, bool) {
        if key.starts_with("secrets/") {
            ("secrets", true)
        } else {
            ("state", false)
        }
    }
    pub fn get(key: &str) -> Result<Option<Vec<u8>>, String> {
        let (n, _) = ns(key);
        store::get(n, key).map_err(|e| e.to_string())
    }
    pub fn put(key: &str, value: &[u8], secret: bool) -> Result<(), String> {
        let (n, s) = ns(key);
        store::put(n, key, value, secret || s).map_err(|e| e.to_string())
    }
    pub fn put_new(key: &str, value: &[u8], secret: bool) -> Result<(), String> {
        let (n, s) = ns(key);
        store::put_new(n, key, value, secret || s).map_err(|e| e.to_string())
    }
    pub fn delete(key: &str) -> Result<(), String> {
        let (n, _) = ns(key);
        store::delete(n, key).map_err(|e| e.to_string())
    }
    pub fn delete_if_value(key: &str, expected: &[u8]) -> Result<(), String> {
        let (n, _) = ns(key);
        store::delete_if_value(n, key, expected).map_err(|e| e.to_string())
    }
    pub fn list(prefix: &str) -> Result<Vec<String>, String> {
        let (n, _) = ns(prefix);
        store::list(n, prefix).map_err(|e| e.to_string())
    }
    pub fn vfs_read(path: &str) -> Result<Vec<u8>, String> {
        vfs::read(path).map_err(|e| e.to_string())
    }
    pub fn sign(wallet: &str, hash: &[u8], intent: &str) -> Result<Sign, String> {
        let r = sign::sign_hash(wallet, hash, intent).map_err(|e| e.to_string())?;
        match r {
            sign::SignResult::Signature(s) => Ok(Sign::Signature(s)),
            sign::SignResult::ApprovalRequired(a) => Ok(Sign::Approval {
                action_id: a.action_id,
                ceremony_url: a.ceremony_url,
                expires_ms: a.expires_ms,
            }),
        }
    }
    pub enum Sign {
        Signature(Vec<u8>),
        Approval {
            action_id: String,
            ceremony_url: String,
            expires_ms: u64,
        },
    }
    pub fn stage(
        wallet: &str,
        chain: &str,
        to: &str,
        value: &str,
        data: &str,
    ) -> Result<tx::StagedTransaction, String> {
        tx::stage(&tx::EvmTransaction {
            wallet: wallet.into(),
            chain: chain.into(),
            to: to.into(),
            value_wei: value.into(),
            data_hex: data.into(),
            nonce: None,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
        })
        .map_err(|e| e.to_string())
    }
    pub fn inspect(wallet: &str, chain: &str, id: &str) -> Result<tx::Inspection, String> {
        tx::inspect(wallet, chain, id).map_err(|e| e.to_string())
    }
    pub fn tx_to_json(v: &tx::StagedTransaction) -> serde_json::Value {
        serde_json::json!({"outbox_id":v.outbox_id,"plan_md":v.plan_md,"approval":v.approval.as_ref().map(|a|serde_json::json!({"action_id":a.action_id,"ceremony_url":a.ceremony_url,"expires_ms":a.expires_ms}))})
    }
    pub fn fail(e: impl Into<String>) -> DispatchResponse {
        error(-4, e)
    }
}

#[macro_export]
macro_rules! route_file {
    (spec: $spec:expr, read: $read:expr, write: $write:expr) => {
        pub struct Route;
        impl $crate::RawGuest for Route {
            fn metadata(c: $crate::RawCtx) -> Result<$crate::RouteMeta, $crate::RouteError> {
                let c = $crate::Ctx::bind::<crate::__PetalRouteIdentity>(c);
                $crate::metadata(&c, $spec)
            }
            fn lookup(c: $crate::RawCtx) -> Result<$crate::Entry, $crate::RouteError> {
                let c = $crate::Ctx::bind::<crate::__PetalRouteIdentity>(c);
                Ok($crate::petal_entry(&c, $spec))
            }
            fn list(_: $crate::RawCtx) -> Result<Vec<$crate::Entry>, $crate::RouteError> {
                Err($crate::RouteError::Invalid("not a directory".into()))
            }
            fn read(c: $crate::RawCtx) -> Result<Vec<u8>, $crate::RouteError> {
                let c = $crate::Ctx::bind::<crate::__PetalRouteIdentity>(c);
                $crate::framework_read(($read)(&c))
            }
            fn write(c: $crate::RawCtx, b: Vec<u8>) -> Result<(), $crate::RouteError> {
                let c = $crate::Ctx::bind::<crate::__PetalRouteIdentity>(c);
                $crate::framework_write(($write)(&c, &b))
            }
        }
    };
    (spec: $spec:expr, read: $read:expr) => {
        pub struct Route;
        impl $crate::RawGuest for Route {
            fn metadata(c: $crate::RawCtx) -> Result<$crate::RouteMeta, $crate::RouteError> {
                let c = $crate::Ctx::bind::<crate::__PetalRouteIdentity>(c);
                $crate::metadata(&c, $spec)
            }
            fn lookup(c: $crate::RawCtx) -> Result<$crate::Entry, $crate::RouteError> {
                let c = $crate::Ctx::bind::<crate::__PetalRouteIdentity>(c);
                Ok($crate::petal_entry(&c, $spec))
            }
            fn list(_: $crate::RawCtx) -> Result<Vec<$crate::Entry>, $crate::RouteError> {
                Err($crate::RouteError::Invalid("not a directory".into()))
            }
            fn read(c: $crate::RawCtx) -> Result<Vec<u8>, $crate::RouteError> {
                let c = $crate::Ctx::bind::<crate::__PetalRouteIdentity>(c);
                $crate::framework_read(($read)(&c))
            }
            fn write(_: $crate::RawCtx, _: Vec<u8>) -> Result<(), $crate::RouteError> {
                Err($crate::RouteError::Denied("path is not writable".into()))
            }
        }
    };
    (spec: $spec:expr, write: $write:expr) => {
        pub struct Route;
        impl $crate::RawGuest for Route {
            fn metadata(c: $crate::RawCtx) -> Result<$crate::RouteMeta, $crate::RouteError> {
                let c = $crate::Ctx::bind::<crate::__PetalRouteIdentity>(c);
                $crate::metadata(&c, $spec)
            }
            fn lookup(c: $crate::RawCtx) -> Result<$crate::Entry, $crate::RouteError> {
                let c = $crate::Ctx::bind::<crate::__PetalRouteIdentity>(c);
                Ok($crate::petal_entry(&c, $spec))
            }
            fn list(_: $crate::RawCtx) -> Result<Vec<$crate::Entry>, $crate::RouteError> {
                Err($crate::RouteError::Invalid("not a directory".into()))
            }
            fn read(c: $crate::RawCtx) -> Result<Vec<u8>, $crate::RouteError> {
                let _ = $crate::Ctx::bind::<crate::__PetalRouteIdentity>(c);
                Err($crate::RouteError::Denied(
                    "path has no read handler".into(),
                ))
            }
            fn write(c: $crate::RawCtx, b: Vec<u8>) -> Result<(), $crate::RouteError> {
                let c = $crate::Ctx::bind::<crate::__PetalRouteIdentity>(c);
                $crate::framework_write(($write)(&c, &b))
            }
        }
    };
    (spec: $spec:expr, list: $children:expr) => {
        pub struct Route;
        impl $crate::RawGuest for Route {
            fn metadata(c: $crate::RawCtx) -> Result<$crate::RouteMeta, $crate::RouteError> {
                let c = $crate::Ctx::bind::<crate::__PetalRouteIdentity>(c);
                $crate::metadata(&c, $spec)
            }
            fn lookup(c: $crate::RawCtx) -> Result<$crate::Entry, $crate::RouteError> {
                let c = $crate::Ctx::bind::<crate::__PetalRouteIdentity>(c);
                Ok($crate::petal_entry(&c, $spec))
            }
            fn list(_: $crate::RawCtx) -> Result<Vec<$crate::Entry>, $crate::RouteError> {
                Ok($children)
            }
            fn read(_: $crate::RawCtx) -> Result<Vec<u8>, $crate::RouteError> {
                Err($crate::RouteError::Invalid("not a file".into()))
            }
            fn write(_: $crate::RawCtx, _: Vec<u8>) -> Result<(), $crate::RouteError> {
                Err($crate::RouteError::Denied("path is not writable".into()))
            }
        }
    };
    (spec: $spec:expr, ctx_list: $children:expr) => {
        pub struct Route;
        impl $crate::RawGuest for Route {
            fn metadata(c: $crate::RawCtx) -> Result<$crate::RouteMeta, $crate::RouteError> {
                let c = $crate::Ctx::bind::<crate::__PetalRouteIdentity>(c);
                $crate::metadata(&c, $spec)
            }
            fn lookup(c: $crate::RawCtx) -> Result<$crate::Entry, $crate::RouteError> {
                let c = $crate::Ctx::bind::<crate::__PetalRouteIdentity>(c);
                Ok($crate::petal_entry(&c, $spec))
            }
            fn list(c: $crate::RawCtx) -> Result<Vec<$crate::Entry>, $crate::RouteError> {
                let c = $crate::Ctx::bind::<crate::__PetalRouteIdentity>(c);
                Ok(($children)(&c))
            }
            fn read(_: $crate::RawCtx) -> Result<Vec<u8>, $crate::RouteError> {
                Err($crate::RouteError::Invalid("not a file".into()))
            }
            fn write(_: $crate::RawCtx, _: Vec<u8>) -> Result<(), $crate::RouteError> {
                Err($crate::RouteError::Denied("path is not writable".into()))
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_adapter_accepts_only_write_successes() {
        assert!(framework_write(DispatchResponse::Write).is_ok());
        assert!(matches!(
            framework_write(DispatchResponse::Read(Vec::new())),
            Err(RouteError::Backend(_))
        ));
    }
}
