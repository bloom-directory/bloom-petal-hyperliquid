use serde::Serialize;

/// The release build may embed the organization's own builder address so
/// `approve_builder_fee.json` callers do not have to know or supply it. This
/// is public on-chain data, not a credential, so unlike a secret API key
/// there is no encryption-at-rest framing — only whether a default is
/// present, and if so, whether it came from a release build or an operator
/// override that can change it without cutting a new release.
const EMBEDDED_DEFAULT_BUILDER: Option<&str> = option_env!("HYPERLIQUID_BUILDER_ADDRESS");

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BuilderAddressSource {
    StoreOverride,
    EmbeddedRelease,
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
/// embedded default, else none.
fn resolve_default(
    embedded: Option<&str>,
    store_override: Option<&str>,
) -> Option<(String, BuilderAddressSource)> {
    if let Some(address) = store_override {
        return Some((address.to_owned(), BuilderAddressSource::StoreOverride));
    }
    embedded.map(|address| (address.to_owned(), BuilderAddressSource::EmbeddedRelease))
}

/// Resolves the builder address an `approve_builder_fee.json` call should
/// use: the caller's explicit value first, else the resolved default, else
/// an error naming what is missing.
pub fn resolve_builder_address(
    explicit: Option<&str>,
    embedded: Option<&str>,
    store_override: Option<&str>,
) -> Result<String, String> {
    if let Some(address) = explicit {
        return Ok(address.to_owned());
    }
    resolve_default(embedded, store_override)
        .map(|(address, _)| address)
        .ok_or_else(|| "builder address is required; no default builder is configured".into())
}

/// Convenience wrapper baking in this release's embedded default so callers
/// only need to supply the caller-explicit value and the store override.
pub fn resolve_default_builder_address(
    explicit: Option<&str>,
    store_override: Option<&str>,
) -> Result<String, String> {
    resolve_builder_address(explicit, EMBEDDED_DEFAULT_BUILDER, store_override)
}

fn builder_address_status(
    embedded: Option<&str>,
    store_override: Option<&str>,
) -> BuilderAddressStatus {
    match resolve_default(embedded, store_override) {
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
    builder_address_status(EMBEDDED_DEFAULT_BUILDER, store_override)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_address_always_wins_over_store_override_and_embedded_default() {
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
    fn store_override_wins_over_embedded_default() {
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
    fn embedded_default_used_when_no_override_is_stored() {
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
    fn this_dev_build_has_no_embedded_default() {
        // This binary is not built with HYPERLIQUID_BUILDER_ADDRESS set, so a
        // dev build has no embedded default; release builds set the env var
        // and `resolve_default_builder_address` would resolve to it instead.
        assert_eq!(EMBEDDED_DEFAULT_BUILDER, None);
        assert!(resolve_default_builder_address(None, None).is_err());
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

        let embedded =
            builder_address_status(Some("0x0000000000000000000000000000000000000002"), None);
        assert!(embedded.configured);
        assert_eq!(embedded.source, BuilderAddressSource::EmbeddedRelease);
        assert_eq!(
            embedded.address,
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
