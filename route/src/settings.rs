use serde::Serialize;

/// This release's default builder **address**, used when an
/// `approve_builder_fee.json` caller omits `builder` and no operator override
/// is stored. A release build embeds it from the `HYPERLIQUID_BUILDER_ADDRESS`
/// build input; a local build sets nothing, so callers must name a builder.
///
/// The address is public on-chain data, not a credential. It is injected at
/// build time rather than committed because this repository is public, and
/// the cost is real: a tagged release cannot be rebuilt byte for byte from
/// its source alone.
///
/// An earlier version of this comment said the compensating control was that
/// "every approval ceremony states the builder, the cap, and which source the
/// address came from". **That is not true end to end at the pinned Bloom and
/// Broker revisions.** The advisory this Petal builds is reduced to
/// `advisory_digest` in `bloom-daemon`, `sign_or_prepare_petal` in
/// `bloom-vfs::exact_signing` takes no advisory at all, and the pinned
/// `bloom-broker-api` has no field for one; the Broker's ceremony does have an
/// `attributed_advisory_items` list, but nothing outside its tests populates
/// it. The digest binds the advisory to the signing identity, so a changed
/// advisory invalidates an approval — it is bound and not displayed.
///
/// So today the owner taps a passkey over an opaque preimage. For an
/// `approveBuilderFee` action the typed message does carry the builder and the
/// rate, but only `hashStruct` enters the preimage, so neither is recoverable
/// from what is shown. Until the advisory is delivered, the builder address is
/// effectively approved sight unseen, which is tracked as a pre-merge gate in
/// the pull request rather than papered over here.
///
/// Set it as a lowercase `0x` address;
/// `release_default_if_set_is_a_lowercase_address` checks whatever a build
/// embeds, so a checksummed or padded value cannot make every call that omits
/// `builder` fail.
///
/// Hyperliquid identifies a builder by address and takes the fee per order,
/// bounded by a cap the user approved on-chain for that address. That is a
/// different model from Polymarket, which identifies a builder by an opaque
/// `bytes32` code whose rates live on the builder's profile with no per-user
/// approval, so the two are named apart throughout: address and fee here,
/// code there.
pub const EMBEDDED_DEFAULT_BUILDER_ADDRESS: Option<&str> =
    checked_embedded_builder_address(option_env!("HYPERLIQUID_BUILDER_ADDRESS"));

/// Rejects a malformed embedded builder address while compiling.
///
/// `option_env!` takes whatever the build environment holds, and this value
/// used to be parsed only when an order was placed: a release built with
/// `HYPERLIQUID_BUILDER_ADDRESS=abc` compiled every route and packaged
/// cleanly, failing at runtime on a Petal nobody could use. The release
/// workflow does not run the test that catches that, and the env var can be
/// set without going through `scripts/build.sh` at all, so the check has to be
/// the build itself.
///
/// Lowercase is required rather than normalized, for the same reason
/// `approve_builder_fee` requires it: the per-order builder field must match
/// an approval byte for byte, so the two can never drift.
const fn checked_embedded_builder_address(value: Option<&str>) -> Option<&str> {
    let Some(address) = value else {
        return None;
    };
    let bytes = address.as_bytes();
    // A build that sets nothing has no default; an empty value says the same.
    if bytes.is_empty() {
        return None;
    }
    assert!(
        bytes.len() == 42 && bytes[0] == b'0' && bytes[1] == b'x',
        "HYPERLIQUID_BUILDER_ADDRESS must be 0x followed by 40 lowercase hex digits"
    );
    let mut i = 2;
    while i < 42 {
        assert!(
            matches!(bytes[i], b'0'..=b'9' | b'a'..=b'f'),
            "HYPERLIQUID_BUILDER_ADDRESS must be 0x followed by 40 lowercase hex digits"
        );
        i += 1;
    }
    Some(address)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BuilderAddressSource {
    StoreOverride,
    ReleaseDefault,
    Unconfigured,
}

#[derive(Debug, Serialize)]
pub struct BuilderAddressStatus {
    pub configured: bool,
    pub source: BuilderAddressSource,
    pub address: Option<String>,
}

/// Resolves the default builder address `approve_builder_fee.json` falls
/// back to when the caller omits `builder`: an operator-set store override
/// first, so the default can change without a release, then this release's
/// source-declared default, else none.
fn resolve_default(
    release_default: Option<&str>,
    store_override: Option<&str>,
) -> Option<(String, BuilderAddressSource)> {
    if let Some(address) = store_override {
        return Some((address.to_owned(), BuilderAddressSource::StoreOverride));
    }
    release_default.map(|address| (address.to_owned(), BuilderAddressSource::ReleaseDefault))
}

/// Resolves the builder address an `approve_builder_fee.json` call should
/// use: the caller's explicit value first, else the resolved default, else
/// an error naming what is missing.
pub fn resolve_builder_address(
    explicit: Option<&str>,
    release_default: Option<&str>,
    store_override: Option<&str>,
) -> Result<String, String> {
    if let Some(address) = explicit {
        return Ok(address.to_owned());
    }
    resolve_default(release_default, store_override)
        .map(|(address, _)| address)
        .ok_or_else(|| "builder address is required; no default builder is configured".into())
}

/// Convenience wrapper baking in this release's declared default so callers
/// only need to supply the caller-explicit value and the store override.
pub fn resolve_default_builder_address(
    explicit: Option<&str>,
    store_override: Option<&str>,
) -> Result<String, String> {
    resolve_builder_address(explicit, EMBEDDED_DEFAULT_BUILDER_ADDRESS, store_override)
}

fn builder_address_status(
    release_default: Option<&str>,
    store_override: Option<&str>,
) -> BuilderAddressStatus {
    match resolve_default(release_default, store_override) {
        Some((address, source)) => BuilderAddressStatus {
            configured: true,
            source,
            address: Some(address),
        },
        None => BuilderAddressStatus {
            configured: false,
            source: BuilderAddressSource::Unconfigured,
            address: None,
        },
    }
}

pub fn default_builder_address_status(store_override: Option<&str>) -> BuilderAddressStatus {
    builder_address_status(EMBEDDED_DEFAULT_BUILDER_ADDRESS, store_override)
}

#[cfg(test)]
mod tests {
    /// A release built with a malformed address used to package cleanly and
    /// fail only when an order was placed. These exercise the same `const fn`
    /// the build evaluates; a bad value makes `cargo build` itself fail, which
    /// a test in this crate cannot assert from the inside.
    #[test]
    fn an_embedded_builder_address_must_be_lowercase_hex() {
        assert_eq!(
            super::checked_embedded_builder_address(Some(
                "0xabcdef0123456789abcdef0123456789abcdef01"
            )),
            Some("0xabcdef0123456789abcdef0123456789abcdef01")
        );
        // A build that sets nothing, or sets it empty, has no default.
        assert_eq!(super::checked_embedded_builder_address(None), None);
        assert_eq!(super::checked_embedded_builder_address(Some("")), None);
    }

    #[test]
    #[should_panic(expected = "40 lowercase hex digits")]
    fn a_short_embedded_builder_address_is_refused() {
        let _ = super::checked_embedded_builder_address(Some("abc"));
    }

    #[test]
    #[should_panic(expected = "40 lowercase hex digits")]
    fn an_uppercase_embedded_builder_address_is_refused() {
        // Normalizing would let the embedded default drift from the per-order
        // builder field, which must match an approval byte for byte.
        let _ = super::checked_embedded_builder_address(Some(
            "0xABCDEF0123456789ABCDEF0123456789ABCDEF01",
        ));
    }

    use super::*;

    #[test]
    fn explicit_address_always_wins_over_store_override_and_release_default() {
        assert_eq!(
            resolve_builder_address(
                Some("0x0000000000000000000000000000000000000001"),
                Some("0x0000000000000000000000000000000000000002"),
                Some("0x0000000000000000000000000000000000000003"),
            ),
            Ok("0x0000000000000000000000000000000000000001".into())
        );
    }

    #[test]
    fn store_override_wins_over_release_default() {
        assert_eq!(
            resolve_builder_address(
                None,
                Some("0x0000000000000000000000000000000000000002"),
                Some("0x0000000000000000000000000000000000000003"),
            ),
            Ok("0x0000000000000000000000000000000000000003".into())
        );
    }

    #[test]
    fn release_default_used_when_no_override_is_stored() {
        assert_eq!(
            resolve_builder_address(
                None,
                Some("0x0000000000000000000000000000000000000002"),
                None,
            ),
            Ok("0x0000000000000000000000000000000000000002".into())
        );
    }

    #[test]
    fn nothing_configured_is_an_explicit_error() {
        assert!(resolve_builder_address(None, None, None).is_err());
    }

    #[test]
    fn release_default_if_set_is_a_lowercase_address() {
        // The default is public data declared in source, so the checks the
        // per-order and override fields get apply to it here: a checksummed
        // or padded value would make every call that omits `builder` fail
        // with "builder address must be lowercase".
        if let Some(address) = EMBEDDED_DEFAULT_BUILDER_ADDRESS {
            assert_eq!(address, address.to_ascii_lowercase());
            assert!(crate::parse_address(address).is_ok());
        }
    }

    #[test]
    fn the_release_wrapper_resolves_exactly_this_release_default() {
        // Whatever this release declares (including nothing), the wrapper
        // resolves exactly that when the caller and the store are silent,
        // and a store override still wins over it. The no-default case
        // itself is `nothing_configured_is_an_explicit_error`, with an
        // explicit `None`, so setting a release default breaks no test.
        assert_eq!(
            resolve_default_builder_address(None, None).ok(),
            EMBEDDED_DEFAULT_BUILDER_ADDRESS.map(str::to_owned)
        );
        assert_eq!(
            resolve_default_builder_address(
                None,
                Some("0x0000000000000000000000000000000000000003")
            ),
            Ok("0x0000000000000000000000000000000000000003".into())
        );
    }

    #[test]
    fn status_reports_the_resolved_source_and_address() {
        let unconfigured = builder_address_status(None, None);
        assert!(!unconfigured.configured);
        assert_eq!(unconfigured.source, BuilderAddressSource::Unconfigured);
        assert_eq!(unconfigured.address, None);

        let release_default =
            builder_address_status(Some("0x0000000000000000000000000000000000000002"), None);
        assert!(release_default.configured);
        assert_eq!(release_default.source, BuilderAddressSource::ReleaseDefault);
        assert_eq!(
            release_default.address,
            Some("0x0000000000000000000000000000000000000002".into())
        );

        let overridden = builder_address_status(
            Some("0x0000000000000000000000000000000000000002"),
            Some("0x0000000000000000000000000000000000000003"),
        );
        assert!(overridden.configured);
        assert_eq!(overridden.source, BuilderAddressSource::StoreOverride);
        assert_eq!(
            overridden.address,
            Some("0x0000000000000000000000000000000000000003".into())
        );
    }
}
