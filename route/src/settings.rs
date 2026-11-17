use serde::Serialize;

/// This release's default builder **address**, used when an
/// `approve_builder_fee.json` caller omits `builder`. A release build embeds
/// it from the `HYPERLIQUID_BUILDER_ADDRESS` build input; a local build sets
/// nothing, so callers must name a builder. There is no operator override:
/// any caller wanting another builder passes `builder` explicitly.
///
/// The address is public on-chain data, not a credential. It is injected at
/// build time rather than committed because this repository is public, and
/// the cost is real: a tagged release cannot be rebuilt byte for byte from
/// its source alone.
///
/// What shows the owner which builder they are authorizing is the signed typed
/// data, not an advisory: `approve_builder_fee` signs an `approveBuilderFee`
/// message whose `builder` and `maxFeeRate` leaves travel in the payload's
/// `bloom.message.review.v1` envelope, which Broker checks against the exact
/// preimage hash before rendering. That rendering needs Bloom #224 and Broker
/// #103; until they land the leaves are not displayed, which the README tracks
/// as a pre-merge gate.
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
/// `option_env!` takes whatever the build environment holds, so a malformed
/// value would otherwise reach a release and fail only when an order was
/// placed. The check is the build, not `scripts/build.sh`, because the
/// variable can be set without going through that script, and not a test,
/// because the release workflow does not run the suite.
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
    ReleaseDefault,
    Unconfigured,
}

#[derive(Debug, Serialize)]
pub struct BuilderAddressStatus {
    pub configured: bool,
    pub source: BuilderAddressSource,
    pub address: Option<String>,
}

/// Resolves the default builder address `approve_builder_fee.json` falls back
/// to when the caller omits `builder`: this release's embedded default, else
/// none. A caller that wants any other builder passes `builder` explicitly.
fn resolve_default(release_default: Option<&str>) -> Option<(String, BuilderAddressSource)> {
    release_default.map(|address| (address.to_owned(), BuilderAddressSource::ReleaseDefault))
}

/// Resolves the builder address an `approve_builder_fee.json` call should
/// use: the caller's explicit value first, else the resolved default, else
/// an error naming what is missing.
pub fn resolve_builder_address(
    explicit: Option<&str>,
    release_default: Option<&str>,
) -> Result<String, String> {
    if let Some(address) = explicit {
        return Ok(address.to_owned());
    }
    resolve_default(release_default)
        .map(|(address, _)| address)
        .ok_or_else(|| "builder address is required; no default builder is configured".into())
}

/// Convenience wrapper baking in this release's declared default so callers
/// only need to supply the caller-explicit value.
pub fn resolve_default_builder_address(explicit: Option<&str>) -> Result<String, String> {
    resolve_builder_address(explicit, EMBEDDED_DEFAULT_BUILDER_ADDRESS)
}

fn builder_address_status(release_default: Option<&str>) -> BuilderAddressStatus {
    match resolve_default(release_default) {
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

pub fn default_builder_address_status() -> BuilderAddressStatus {
    builder_address_status(EMBEDDED_DEFAULT_BUILDER_ADDRESS)
}

#[cfg(test)]
mod tests {
    /// These exercise the same `const fn` the build evaluates. A malformed
    /// value makes `cargo build` itself fail, which a test inside this crate
    /// cannot assert, so these cover the validator rather than the build.
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
    fn an_explicit_address_always_wins_over_the_release_default() {
        assert_eq!(
            resolve_builder_address(
                Some("0x0000000000000000000000000000000000000001"),
                Some("0x0000000000000000000000000000000000000002"),
            ),
            Ok("0x0000000000000000000000000000000000000001".into())
        );
    }

    #[test]
    fn the_release_default_is_used_when_the_caller_is_silent() {
        assert_eq!(
            resolve_builder_address(None, Some("0x0000000000000000000000000000000000000002")),
            Ok("0x0000000000000000000000000000000000000002".into())
        );
    }

    #[test]
    fn nothing_configured_is_an_explicit_error() {
        assert!(resolve_builder_address(None, None).is_err());
    }

    #[test]
    fn release_default_if_set_is_a_lowercase_address() {
        // The default is public data embedded at build time, so the check the
        // per-order field gets applies to it here too: a checksummed or padded
        // value would make every call that omits `builder` fail with
        // "builder address must be lowercase".
        if let Some(address) = EMBEDDED_DEFAULT_BUILDER_ADDRESS {
            assert_eq!(address, address.to_ascii_lowercase());
            assert!(crate::parse_address(address).is_ok());
        }
    }

    #[test]
    fn the_release_wrapper_resolves_exactly_this_release_default() {
        // Whatever this release declares, including nothing, the wrapper
        // resolves exactly that when the caller is silent. The no-default case
        // is `nothing_configured_is_an_explicit_error`, with an explicit
        // `None`, so embedding a default breaks no test.
        assert_eq!(
            resolve_default_builder_address(None).ok(),
            EMBEDDED_DEFAULT_BUILDER_ADDRESS.map(str::to_owned)
        );
    }

    #[test]
    fn status_reports_the_resolved_source_and_address() {
        let unconfigured = builder_address_status(None);
        assert!(!unconfigured.configured);
        assert_eq!(unconfigured.source, BuilderAddressSource::Unconfigured);
        assert_eq!(unconfigured.address, None);

        let release_default =
            builder_address_status(Some("0x0000000000000000000000000000000000000002"));
        assert!(release_default.configured);
        assert_eq!(release_default.source, BuilderAddressSource::ReleaseDefault);
        assert_eq!(
            release_default.address,
            Some("0x0000000000000000000000000000000000000002".into())
        );
    }
}
