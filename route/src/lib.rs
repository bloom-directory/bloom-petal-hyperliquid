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
        let source = include_str!("../files/[network]/agent_sessions/[wallet]/new.json.rs");
        assert!(source.contains("bloom:key.derive"));
    }
}
