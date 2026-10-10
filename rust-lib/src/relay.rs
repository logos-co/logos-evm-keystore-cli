//! Logos-free helpers: argument normalisation and refusal translation.

use serde_json::{json, Value};

/// Drop exactly one trailing newline: `@file` hands over the file verbatim, and a
/// password file written with `echo` ends in one.
pub fn strip_file_newline(s: &str) -> &str {
    s.strip_suffix("\r\n").or_else(|| s.strip_suffix('\n')).unwrap_or(s)
}

/// The exact `configure` command that adds `me` to `role` while keeping every name
/// already in force — `configure` is total, so a hint naming only `me` would strip
/// the GUI surfaces, and one without the managers would stop the signer manager signing.
pub fn configure_hint(identity: &Value, me: &str, role: &str) -> String {
    let list = |key: &str| -> Vec<String> {
        identity
            .get(key)
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
            .unwrap_or_default()
    };
    let mut approvers = list("approvers");
    let mut custodians = list("custodians");
    let target = if role == "approvers" { &mut approvers } else { &mut custodians };
    if !target.iter().any(|n| n == me) {
        target.push(me.to_string());
    }
    let mut doc = json!({ "approvers": approvers, "custodians": custodians });
    // Only where the keystore has the role: an older one refuses a key it does not know.
    if identity.get("managers").is_some() {
        doc["managers"] = json!(list("managers"));
    }
    format!("logosctl call keystore_module configure '{doc}'")
}

/// The `configure` command that adds `me` to the signer manager's custodians, keeping its
/// approvers and signers: it is total too, and a document without the signers signs nothing.
pub fn manager_configure_hint(identity: &Value, me: &str) -> String {
    let list = |key: &str| -> Vec<String> {
        identity
            .get(key)
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
            .unwrap_or_default()
    };
    let mut custodians = list("custodians");
    if !custodians.iter().any(|n| n == me) {
        custodians.push(me.to_string());
    }
    let mut signers = list("signers");
    if signers.is_empty() {
        signers.push("keystore_module".into());
    }
    let doc = json!({ "approvers": list("approvers"), "custodians": custodians, "signers": signers });
    format!("logosctl call signer_manager_module configure '{doc}'")
}

/// A manager reply, with its opaque refusal turned into the fix, as `translate_refusal` does.
pub fn translate_manager_refusal(reply: &str, hint: impl FnOnce() -> String) -> String {
    let Ok(mut v) = serde_json::from_str::<Value>(reply) else {
        return reply.to_string();
    };
    if v.get("ok").and_then(Value::as_bool) == Some(false)
        && v.get("error").and_then(Value::as_str) == Some("not authorized")
    {
        v["error"] = Value::String(format!(
            "not authorized: evm_keystore_cli is not the signer manager's custodian. Run: {}",
            hint()
        ));
        return v.to_string();
    }
    reply.to_string()
}

pub fn holds(identity: &Value, me: &str, role: &str) -> bool {
    identity
        .get(role)
        .and_then(Value::as_array)
        .map(|a| a.iter().any(|v| v.as_str() == Some(me)))
        .unwrap_or(false)
}

pub fn not_custodian(hint: &str) -> String {
    format!("not authorized: evm_keystore_cli is not a configured custodian. Run: {hint}")
}

/// A keystore reply, with its one opaque refusal turned into a sentence that names the
/// fix. Everything else passes through untouched.
pub fn translate_refusal(reply: &str, hint: impl FnOnce() -> String) -> String {
    let Ok(mut v) = serde_json::from_str::<Value>(reply) else {
        return reply.to_string();
    };
    if v.get("ok").and_then(Value::as_bool) == Some(false)
        && v.get("error").and_then(Value::as_str) == Some("not authorized")
    {
        v["error"] = Value::String(not_custodian(&hint()));
        return v.to_string();
    }
    reply.to_string()
}

/// Best-effort: overwrite the bytes before the allocation is returned.
pub fn scrub(s: &mut String) {
    unsafe { s.as_mut_vec().fill(0) };
    s.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_file_newline_drops_exactly_one() {
        assert_eq!(strip_file_newline("pw\n"), "pw");
        assert_eq!(strip_file_newline("pw\r\n"), "pw");
        assert_eq!(strip_file_newline("pw\n\n"), "pw\n");
        assert_eq!(strip_file_newline("pw"), "pw");
    }

    #[test]
    fn the_hint_is_total_safe() {
        let id = json!({ "approvers": ["evm_signer_ui"], "custodians": ["evm_keystore_ui"] });
        assert_eq!(
            configure_hint(&id, "evm_keystore_cli", "custodians"),
            r#"logosctl call keystore_module configure '{"approvers":["evm_signer_ui"],"custodians":["evm_keystore_ui","evm_keystore_cli"]}'"#
        );
        let already = json!({ "approvers": [], "custodians": ["evm_keystore_cli"] });
        assert!(configure_hint(&already, "evm_keystore_cli", "custodians").contains(r#""custodians":["evm_keystore_cli"]"#));
        // A keystore with the managers role keeps it: without it, nothing signs.
        let managed = json!({ "approvers": [], "custodians": [], "managers": ["signer_manager_module"] });
        assert!(configure_hint(&managed, "evm_keystore_cli", "custodians")
            .ends_with(r#"{"approvers":[],"custodians":["evm_keystore_cli"],"managers":["signer_manager_module"]}'"#));
    }

    #[test]
    fn the_manager_hint_adds_this_custodian_and_keeps_the_rest() {
        let id = json!({ "approvers": ["evm_signer_ui"], "custodians": ["evm_keystore_ui"], "signers": ["keystore_module", "ledger_module"] });
        assert_eq!(
            manager_configure_hint(&id, "evm_keystore_cli"),
            r#"logosctl call signer_manager_module configure '{"approvers":["evm_signer_ui"],"custodians":["evm_keystore_ui","evm_keystore_cli"],"signers":["keystore_module","ledger_module"]}'"#
        );
        // Nothing read back still names a signer: a total document without one would sign nothing.
        assert!(manager_configure_hint(&json!({}), "evm_keystore_cli").contains(r#""signers":["keystore_module"]"#));
        let refused = translate_manager_refusal(r#"{"ok":false,"error":"not authorized"}"#, || "HINT".into());
        assert!(refused.contains("not the signer manager's custodian. Run: HINT"), "{refused}");
    }

    #[test]
    fn only_the_opaque_refusal_is_translated() {
        let hint = "logosctl call keystore_module configure '{}'";
        let out = translate_refusal(r#"{"ok":false,"error":"not authorized"}"#, || hint.to_string());
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["ok"], false);
        assert!(v["error"].as_str().unwrap().starts_with("not authorized: evm_keystore_cli is not a configured custodian. Run: "));
        assert!(v["error"].as_str().unwrap().ends_with(hint));

        let other = r#"{"ok":false,"error":"word count must be 12/15/18/21/24, got 13"}"#;
        let never = || panic!("hint computed for a reply that needs none");
        assert_eq!(translate_refusal(other, never), other);
        let good = r#"{"ok":true,"phrase":"a b c"}"#;
        assert_eq!(translate_refusal(good, never), good);
        assert_eq!(translate_refusal("garbage", never), "garbage");
    }

    #[test]
    fn holds_reads_the_role_list() {
        let id = json!({ "approvers": ["evm_signer_ui"], "custodians": ["evm_keystore_ui", "evm_keystore_cli"] });
        assert!(holds(&id, "evm_keystore_cli", "custodians"));
        assert!(!holds(&id, "evm_keystore_cli", "approvers"));
    }
}
