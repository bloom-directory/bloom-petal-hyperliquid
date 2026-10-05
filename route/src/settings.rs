use serde::Serialize;

/// This release's default builder address, used when an
/// `approve_builder_fee.json` caller omits `builder` and no operator override
/// is stored. It is public on-chain data, not a credential, so it lives here
/// in source: a release can then be rebuilt byte for byte from its tag, and
/// the package CI tests is the package that ships. Set it as a lowercase `0x`
/// address; `release_default_if_set_is_a_lowercase_address` checks it.
pub const RELEASE_DEFAULT_BUILDER: Option<&str> = None;

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
    resolve_builder_address(explicit, RELEASE_DEFAULT_BUILDER, store_override)
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
    builder_address_status(RELEASE_DEFAULT_BUILDER, store_override)
}

#[cfg(test)]
mod tests {
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
        if let Some(address) = RELEASE_DEFAULT_BUILDER {
            assert_eq!(address, address.to_ascii_lowercase());
            assert!(crate::parse_address(address).is_ok());
        }
    }

    #[test]
    fn no_release_default_means_an_explicit_builder_or_override_is_required() {
        assert_eq!(RELEASE_DEFAULT_BUILDER, None);
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
