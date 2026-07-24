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
