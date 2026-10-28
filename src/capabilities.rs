//! Conservative capability routing inventory. A catalog entry alone does not
//! establish a working implementation, installed provider or upstream parity.

use serde_json::{Value, json};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    Native,
    ExternalProvider,
    Unavailable,
}

impl Capability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::ExternalProvider => "external-provider",
            Self::Unavailable => "unavailable",
        }
    }

    fn explanation(self) -> &'static str {
        match self {
            Self::Native => {
                "A local implementation route exists; behavior and upstream parity still require fixture verification"
            }
            Self::ExternalProvider => {
                "An external CLI, device, service or debugger route exists; readiness depends on a reachable provider"
            }
            Self::Unavailable => {
                "No verified functional route exists in rea-fast, or the implementation explicitly reports unavailable"
            }
        }
    }
}

/// This inventory intentionally errs toward `unavailable` when there is no
/// audited dispatch route. It describes routing, not successful execution.
pub fn classify(name: &str) -> Capability {
    use Capability::{ExternalProvider as External, Native, Unavailable};
    match name {
        // File-local parsing, comparison, inspection and MCP meta-tools.
        "rea_search_tools"
        | "rea_execute_tool"
        | "inspect_asar"
        | "pack_asar"
        | "extract_artifact"
        | "analyze_javascript_application"
        | "analyze_electron_source"
        | "inspect_electron_fuses"
        | "recover_javascript_sources"
        | "extract_sourcemap"
        | "run_audit_pipeline"
        | "scan_secrets"
        | "audit_tauri"
        | "diff_applications"
        | "compare_application_versions"
        | "compare_source_to_bundle"
        | "compare_javascript_export_shapes"
        | "trace_application_feature"
        | "trace_feature"
        | "trace_javascript_semantics"
        | "inspect_binary_layout"
        | "inspect_go_binary"
        | "inspect_rust_binary"
        | "inspect_wasm_artifact"
        | "inspect_android_package"
        | "inspect_sqlite_database"
        | "inspect_packet_capture"
        | "inspect_plist"
        | "project_apple_application_graph"
        | "project_harmony_application_graph"
        | "inspect_managed_artifact"
        | "inspect_managed_members"
        | "inspect_managed_native_boundaries"
        | "inspect_model_artifact"
        | "inspect_desktop_application"
        | "inspect_python_pyc"
        | "inspect_artifact"
        | "inspect_macho"
        | "inspect_signature"
        | "inspect_keyed_archive"
        | "list_architectures"
        | "trace_dylib_resolution"
        | "inspect_byte_entropy"
        | "inspect_native_exports"
        | "compare_wasm_interfaces"
        | "inspect_il2cpp_metadata"
        | "identify_flutter_build"
        | "inspect_apk_signature"
        | "project_android_application_graph"
        | "export_environment_bundle"
        | "list_strings"
        | "search_strings"
        | "list_segments"
        | "list_procedures"
        | "list_names"
        | "get_evidence_bundle"
        | "export_evidence_bundle"
        | "import_evidence_bundle"
        | "record_unknown"
        | "update_unknown"
        | "list_unknowns"
        | "inspect_analysis_view"
        | "compare_artifacts"
        | "compare_bundles" => Native,

        // These operations invoke or connect to an external provider, so
        // success cannot be assumed from their presence in the catalog.
        "list_browser_targets"
        | "list_electron_targets"
        | "list_adb_devices"
        | "inspect_adb_device"
        | "list_adb_packages"
        | "list_live_processes"
        | "inspect_live_process"
        | "execute_gdb"
        | "execute_frida"
        | "inspect_with_objdump"
        | "execute_rizin"
        | "execute_rizin_command"
        | "decode_signal_sigrok"
        | "decode_signal_recording"
        | "decompile_apktool_jadx"
        | "demangle_swift"
        | "start_gdb_session"
        | "gdb_console"
        | "gdb_session_status"
        | "close_gdb_session"
        | "start_rizin_debug_session"
        | "rizin_debug_command"
        | "rizin_debug_session_status"
        | "close_rizin_debug_session"
        | "inspect_web_page"
        | "inspect_electron_page"
        | "capture_web_screenshot"
        | "evaluate_web_script"
        | "export_web_scripts"
        | "inspect_jeb_client"
        | "open_jeb_project"
        | "list_jeb_units"
        | "decompile_jeb_item"
        | "inspect_adb_client"
        | "list_adb_processes"
        | "list_adb_features"
        | "list_adb_services"
        | "list_adb_directory"
        | "inspect_adb_package"
        | "inspect_adb_display"
        | "inspect_adb_window"
        | "read_adb_logcat"
        | "read_adb_setting"
        | "resolve_adb_packages"
        | "pull_adb_file"
        | "push_adb_file"
        | "start_adb_activity"
        | "start_adb_app"
        | "stop_adb_app"
        | "install_adb_package"
        | "uninstall_adb_package"
        | "collect_adb_bugreport"
        | "capture_adb_screen"
        | "pull_adb_package" => External,

        // No verified route: includes known fail-closed stubs and other
        // catalog-only tools. Keep this the safe default.
        _ => Unavailable,
    }
}

pub fn details(name: &str) -> Value {
    let category = classify(name);
    json!({
        "category": category.as_str(),
        "basis": "local_dispatch_route_audit",
        "reason": category.explanation(),
        "upstream_parity": "not_verified",
        "runtime_verified": false
    })
}

pub fn annotate(tool: &Value) -> Value {
    let mut copy = tool.clone();
    if let Some(name) = copy.get("name").and_then(Value::as_str).map(str::to_owned)
        && let Some(map) = copy.as_object_mut()
    {
        map.insert("rea_fast_capability".to_string(), details(&name));
    }
    copy
}

/// Keep the standard MCP tool shape intact while surfacing the support class
/// to clients that only read `tools/list` and never invoke `rea_search_tools`.
pub fn advertise(tool: &Value) -> Value {
    let mut copy = tool.clone();
    let Some(name) = copy.get("name").and_then(Value::as_str) else {
        return copy;
    };
    let summary = match classify(name) {
        Capability::Native => "[REA-Fast native route; parity unverified] ",
        Capability::ExternalProvider => {
            "[REA-Fast external provider required; runtime unverified] "
        }
        Capability::Unavailable => "[UNAVAILABLE in REA-Fast; upstream catalog description only] ",
    };
    if let Some(description) = tool.get("description").and_then(Value::as_str)
        && let Some(map) = copy.as_object_mut()
    {
        map.insert(
            "description".to_string(),
            format!("{summary}{description}").into(),
        );
    }
    copy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_245_tools_have_explicit_conservative_classification() {
        let mut names = std::collections::HashSet::new();
        let mut counts = [0usize; 3];
        for tool in crate::catalog::get_all_tools() {
            let name = tool["name"].as_str().expect("tool name");
            assert!(names.insert(name), "Duplicate tool {name}");
            let category = classify(name);
            let index = match category {
                Capability::Native => 0,
                Capability::ExternalProvider => 1,
                Capability::Unavailable => 2,
            };
            counts[index] += 1;
            assert_eq!(
                annotate(tool)["rea_fast_capability"]["category"],
                category.as_str()
            );
            assert!(
                advertise(tool)["description"]
                    .as_str()
                    .unwrap()
                    .starts_with('[')
            );
        }
        assert_eq!(names.len(), 245);
        assert!(counts.iter().all(|n| *n > 0));
    }

    #[test]
    fn known_stubs_are_never_advertised_as_runnable() {
        for name in [
            "start_frida_session",
            "load_frida_script",
            "compare_web_screenshots",
            "decode_interface_builder",
            "verify_managed_native_boundaries",
            "verify_reconstruction",
            "build_call_path",
            "current_address",
        ] {
            assert_eq!(classify(name), Capability::Unavailable, "{name}");
        }
        assert_eq!(classify("inspect_asar"), Capability::Native);
        assert_eq!(classify("list_adb_devices"), Capability::ExternalProvider);
    }
}
