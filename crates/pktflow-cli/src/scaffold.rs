//! `--scaffold NAME` (10.3): copy the template plugin (06.1) to a new
//! file, pre-filled from an unknown group when one is given. Writes
//! exactly one new file — the registration line in
//! `pktflow-plugins/src/lib.rs` is left for a human, per PRD §8's
//! "touching only its own file plus one registration line" metric.

use std::path::{Path, PathBuf};

use pktflow_flows::UnknownGroup;

use crate::error::CliError;
use crate::render::hex_dump_lines;

/// PascalCase from a snake_case/lowercase plugin name (`"my_proto"` →
/// `"MyProto"`), matching the template's `Template` struct name.
pub fn pascal_case(name: &str) -> String {
    name.split(['_', '-'])
        .filter(|s| !s.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

/// Rewrites the template source into a starter plugin body: struct/name
/// substitution, and — when the group's `UnknownKey.route` is `Some` — a
/// pre-filled `claims()` plus a worked hex-sample doc comment.
pub fn render_plugin_source(
    template_src: &str,
    name: &str,
    group: Option<&UnknownGroup>,
) -> String {
    let struct_name = pascal_case(name);
    let mut out = template_src
        .replace("Template", &struct_name)
        .replace("\"template\"", &format!("{name:?}"));

    if let Some(g) = group {
        if let Some(route) = g.key.route {
            let route_expr = route_literal(route);
            out = out.replace(
                "&[RouteId::Custom {\n            space: \"pktt\",\n            id: 0,\n        }]",
                &format!("&[{route_expr}]"),
            );
        }
        if let Some(sample) = g.samples.front() {
            let hex = hex_dump_lines(sample)
                .into_iter()
                .map(|l| format!("//! `{l}`"))
                .collect::<Vec<_>>()
                .join("\n");
            out = format!(
                "//! Scaffolded from an observed unknown occurrence \
                 (`pktflow unknown --scaffold`, 10.3). First retained sample:\n\
                 {hex}\n//!\n{out}"
            );
        }
    }
    out
}

/// A `RouteId` variant as Rust source (the scaffold needs to emit code,
/// not just a `Display` string).
fn route_literal(route: pktflow_core::RouteId) -> String {
    use pktflow_core::RouteId;
    match route {
        RouteId::LinkType(id) => format!("RouteId::LinkType({id})"),
        RouteId::EtherType(id) => format!("RouteId::EtherType({id:#06x})"),
        RouteId::IpProtocol(id) => format!("RouteId::IpProtocol({id})"),
        RouteId::UdpPort(id) => format!("RouteId::UdpPort({id})"),
        RouteId::TcpPort(id) => format!("RouteId::TcpPort({id})"),
        RouteId::Custom { space, id } => {
            format!("RouteId::Custom {{ space: {space:?}, id: {id} }}")
        }
    }
}

/// Writes the scaffolded source to `dir/<name>.rs`, refusing to clobber
/// an existing file (exit 2, 08.1's usage-error code — this is a starting
/// point, not a merge tool).
pub fn scaffold_plugin(
    dir: &Path,
    name: &str,
    group: Option<&UnknownGroup>,
) -> Result<PathBuf, CliError> {
    let template_path = dir.join("template.rs");
    let template_src = std::fs::read_to_string(&template_path)
        .map_err(|e| CliError::Internal(format!("read {}: {e}", template_path.display())))?;
    let target = dir.join(format!("{name}.rs"));
    if target.exists() {
        return Err(CliError::Usage(format!(
            "{} already exists — --scaffold never overwrites",
            target.display()
        )));
    }
    let source = render_plugin_source(&template_src, name, group);
    std::fs::write(&target, source)?;
    Ok(target)
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use pktflow_core::RouteId;
    use pktflow_flows::{UnknownGroup, UnknownKey};
    use smallvec::SmallVec;

    use super::*;

    const TEMPLATE_SRC: &str = include_str!("../../pktflow-plugins/src/template.rs");

    fn group_with_route(route: RouteId) -> UnknownGroup {
        UnknownGroup {
            key: UnknownKey {
                predecessor: "udp",
                route: Some(route),
            },
            count: 1,
            bytes_total: 4,
            bytes_min: 4,
            bytes_max: 4,
            first_seen: SystemTime::UNIX_EPOCH,
            last_seen: SystemTime::UNIX_EPOCH,
            endpoints: Vec::new(),
            endpoints_overflow: false,
            near_misses: SmallVec::new(),
            samples: [vec![0xDE, 0xAD, 0xBE, 0xEF].into_boxed_slice()]
                .into_iter()
                .collect(),
        }
    }

    #[test]
    fn pascal_case_from_snake_case() {
        assert_eq!(pascal_case("my_proto"), "MyProto");
        assert_eq!(pascal_case("wireguard"), "Wireguard");
    }

    #[test]
    fn renders_name_and_struct_substitution() {
        let out = render_plugin_source(TEMPLATE_SRC, "my_proto", None);
        assert!(out.contains("struct MyProto"));
        assert!(out.contains("impl LayerPlugin for MyProto"));
        assert!(out.contains("\"my_proto\""));
        assert!(!out.contains("struct Template"));
    }

    #[test]
    fn prefills_claims_from_the_group_route() {
        let g = group_with_route(RouteId::UdpPort(4433));
        let out = render_plugin_source(TEMPLATE_SRC, "guessed", Some(&g));
        assert!(out.contains("RouteId::UdpPort(4433)"));
        assert!(out.contains("de ad be ef"));
    }

    #[test]
    fn scaffold_refuses_to_clobber_an_existing_file() {
        let dir =
            std::env::temp_dir().join(format!("pktflow-scaffold-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create test dir");
        std::fs::write(dir.join("template.rs"), TEMPLATE_SRC).expect("write template.rs");
        std::fs::write(dir.join("clobber_me.rs"), "// pre-existing").expect("write clobber_me.rs");

        let err = scaffold_plugin(&dir, "clobber_me", None).expect_err("must refuse to overwrite");
        assert!(matches!(err, CliError::Usage(_)));
        assert_eq!(err.exit_code(), 2);

        let fresh = scaffold_plugin(&dir, "brand_new", None).expect("writes a new file");
        assert!(fresh.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
