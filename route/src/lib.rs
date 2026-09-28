mod protocol;
mod workflow;

pub use protocol::*;
pub use serde_json;
pub use workflow::*;

pub fn static_list(names: &[(&str, bool, bool)]) -> Vec<petal::RouteChild> {
    names
        .iter()
        .map(|(name, is_dir, is_writable)| {
            if *is_dir {
                petal::dir(*name)
            } else if *is_writable {
                petal::writable(*name)
            } else {
                petal::file(*name)
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn agent_session_creation_declares_key_derivation_capability() {
        let source =
            include_str!("../files/[network]/wallets/[wallet]/[index]/agent_sessions/new.json.rs");
        assert!(source.contains("bloom:key.derive"));
    }

    #[test]
    fn session_success_evidence_resolves_to_public_user_routes() {
        let sources = [
            include_str!(
                "../files/[network]/wallets/[wallet]/[index]/agent_sessions/[session]/cancel.json.rs"
            ),
            include_str!(
                "../files/[network]/wallets/[wallet]/[index]/agent_sessions/[session]/update_leverage.json.rs"
            ),
        ];
        for source in sources {
            let path = source
                .split("\"path_from_bloom_root\": \"")
                .nth(1)
                .expect("session help declares a success evidence path")
                .split('"')
                .next()
                .unwrap();
            assert!(
                path.starts_with("petals/hyperliquid/<network>/users/<owner_address>/"),
                "{path}"
            );
            let route = path
                .strip_prefix("petals/hyperliquid/")
                .unwrap()
                .replace("<network>", "[network]")
                .replace("<owner_address>", "[account]")
                .replace("/BTC.json", "/[coin].json");
            let source_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("files")
                .join(format!("{route}.rs"));
            assert!(source_path.is_file(), "evidence route is missing: {route}");
        }
    }
}
