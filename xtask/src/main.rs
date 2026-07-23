use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Clone)]
struct Route {
    path: String,
    source: PathBuf,
    package: String,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1)
    }
}
fn run() -> Result<(), String> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let routes = discover(&root.join("route/files"), &root)?;
    if routes.is_empty() {
        return Err("no route sources".into());
    };
    let build = root.join("target/hyperliquid-routes");
    let workspace = build.join("workspace");
    generate_workspace(&root, &workspace, &routes)?;
    fs::copy(
        root.join("xtask/route-workspace.Cargo.lock"),
        workspace.join("Cargo.lock"),
    )
    .map_err(|e| format!("install pinned route workspace lock: {e}"))?;
    command(
        Command::new("cargo")
            .args([
                "build",
                "--workspace",
                "--target",
                "wasm32-unknown-unknown",
                "--release",
                "--locked",
                "--manifest-path",
            ])
            .arg(workspace.join("Cargo.toml")),
    )?;
    let staging = build.join("staging/petal/hyperliquid");
    if staging.exists() {
        fs::remove_dir_all(&staging).map_err(|e| e.to_string())?
    }
    fs::create_dir_all(&staging).map_err(|e| e.to_string())?;
    for r in &routes {
        let core = workspace
            .join("target/wasm32-unknown-unknown/release")
            .join(format!("{}.wasm", r.package.replace('-', "_")));
        if !core.exists() {
            return Err(format!("missing core wasm {}", core.display()));
        }
        let out = staging.join(format!("{}.wasm", r.path));
        let unstripped = out.with_extension("unstripped.wasm");
        fs::create_dir_all(out.parent().unwrap()).map_err(|e| e.to_string())?;
        command(
            Command::new("wasm-tools")
                .args(["component", "new"])
                .arg(&core)
                .args(["-o"])
                .arg(&unstripped),
        )?;
        command(
            Command::new("wasm-tools")
                .args(["strip", "--all"])
                .arg(&unstripped)
                .args(["-o"])
                .arg(&out),
        )?;
        fs::remove_file(&unstripped).map_err(|e| e.to_string())?;
        command(Command::new("wasm-tools").args(["validate"]).arg(&out))?
    }
    let dest = root.join("petal/hyperliquid");
    if dest.exists() {
        fs::remove_dir_all(&dest).map_err(|e| e.to_string())?
    }
    fs::create_dir_all(dest.parent().unwrap()).map_err(|e| e.to_string())?;
    fs::rename(&staging, &dest).map_err(|e| e.to_string())?;
    println!("built {} Hyperliquid route components", routes.len());
    Ok(())
}
fn discover(dir: &Path, _root: &Path) -> Result<Vec<Route>, String> {
    let mut files = Vec::new();
    walk(dir, &mut files)?;
    files.sort();
    let mut seen = BTreeSet::new();
    files
        .into_iter()
        .map(|source| {
            let rel = source
                .strip_prefix(dir)
                .map_err(|e| e.to_string())?
                .to_string_lossy()
                .replace('\\', "/");
            let path = rel.strip_suffix(".rs").unwrap().to_string();
            let package = format!(
                "hl-route-{}-{}",
                path.chars()
                    .map(|c| if c.is_ascii_alphanumeric() {
                        c.to_ascii_lowercase()
                    } else {
                        '-'
                    })
                    .collect::<String>()
                    .split('-')
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
                    .join("-"),
                &blake3::hash(path.as_bytes()).to_hex()[..10]
            );
            if !seen.insert(path.clone()) {
                return Err(format!("duplicate {path}"));
            }
            Ok(Route {
                path,
                source,
                package,
            })
        })
        .collect()
}
fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    for e in fs::read_dir(dir).map_err(|e| e.to_string())? {
        let p = e.map_err(|e| e.to_string())?.path();
        if p.is_dir() {
            walk(&p, out)?
        } else if p.extension() == Some(OsStr::new("rs")) {
            out.push(p)
        }
    }
    Ok(())
}
fn generate_workspace(root: &Path, workspace: &Path, routes: &[Route]) -> Result<(), String> {
    fs::create_dir_all(workspace.join("members")).map_err(|e| e.to_string())?;
    let members = routes
        .iter()
        .map(|r| format!("\"members/{}\"", r.package))
        .collect::<Vec<_>>()
        .join(",\n");
    fs::write(workspace.join("Cargo.toml"),format!("[workspace]\nresolver=\"2\"\nmembers=[\n{}\n]\n\n[profile.release]\nopt-level=3\nstrip=\"none\"\npanic=\"unwind\"\nincremental=false\n",members)).map_err(|e|e.to_string())?;
    for r in routes {
        let dir = workspace.join("members").join(&r.package);
        fs::create_dir_all(dir.join("src")).map_err(|e| e.to_string())?;
        let params = route_params(&r.path)
            .iter()
            .map(|(n, i)| format!("        ({n:?}, {i}),"))
            .collect::<Vec<_>>()
            .join("\n");
        let source = r
            .source
            .strip_prefix(root)
            .map_err(|e| e.to_string())?
            .to_string_lossy()
            .replace('\\', "/");
        fs::write(dir.join("Cargo.toml"),format!("[package]\nname=\"{}\"\nversion=\"0.1.0\"\nedition=\"2024\"\npublish=false\n[lib]\ncrate-type=[\"cdylib\"]\n[dependencies]\npetal={{path=\"../../../../../sdk\"}}\nhl_route={{package=\"bloom-hyperliquid-petal-route\",path=\"../../../../../route\"}}\n",r.package)).map_err(|e|e.to_string())?;
        fs::write(dir.join("src/lib.rs"),format!("#![allow(dead_code,clippy::too_many_arguments)]\npub struct __PetalRouteIdentity;\nimpl petal::RouteIdentity for __PetalRouteIdentity {{ const PATH:&'static str={:?}; const CANONICAL_PATH:&'static str={:?}; const PARAMS:&'static [(&'static str,usize)]=&[{}]; }}\npub use hl_route::*;\nmod selected_route {{ include!(concat!(env!(\"CARGO_MANIFEST_DIR\"),\"/../../../../../{}\")); }}\nuse selected_route::Route;\npetal::bindings::export!(Route);\n",r.path,canonical(&r.path),params,source)).map_err(|e|e.to_string())?
    }
    Ok(())
}
fn canonical(path: &str) -> String {
    path.strip_suffix("/$index")
        .unwrap_or(if path == "$index" { "" } else { path })
        .into()
}
fn route_params(path: &str) -> Vec<(&str, usize)> {
    path.split('/')
        .enumerate()
        .filter_map(|(i, s)| {
            s.strip_prefix('[')
                .and_then(|x| x.strip_suffix(']'))
                .map(|x| (x, i))
        })
        .collect()
}
fn command(c: &mut Command) -> Result<(), String> {
    let status = c.status().map_err(|e| e.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("command failed: {status}"))
    }
}
