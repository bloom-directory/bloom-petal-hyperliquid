mod protocol;
mod workflow;

pub use protocol::*;
pub use serde_json;
pub use workflow::*;

pub fn route_entry(ctx: &petal::Ctx, spec: petal::Spec) -> petal::Entry {
    petal::petal_entry(ctx, spec)
}

pub fn list(_ctx: &petal::Ctx, names: &[(&str, bool, bool)]) -> Vec<petal::Entry> {
    static_list(names)
}

pub fn static_list(names: &[(&str, bool, bool)]) -> Vec<petal::Entry> {
    names
        .iter()
        .map(|(name, dir, writable)| petal::Entry {
            name: (*name).into(),
            kind: if *dir {
                petal::EntryKind::Dir
            } else {
                petal::EntryKind::File
            },
            mode: if *dir {
                0o755
            } else if *writable {
                0o644
            } else {
                0o444
            },
            size: Some(0),
            link_target: None,
        })
        .collect()
}
