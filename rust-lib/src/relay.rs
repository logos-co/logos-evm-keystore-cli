//! Logos-free helpers: argument normalisation and refusal translation.

use serde_json::{json, Value};

/// Drop exactly one trailing newline: `@file` hands over the file verbatim, and a
/// password file written with `echo` ends in one.
pub fn strip_file_newline(s: &str) -> &str {
    s.strip_suffix("\r\n").or_else(|| s.strip_suffix('\n')).unwrap_or(s)
}

/// The exact `configure` command that adds `me` to `role` while keeping every name
/// already in force — `configure` is total, so a hint naming only `me` would strip
/// the GUI surfaces.
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
    let doc = json!({ "approvers": approvers, "custodians": custodians });
    format!("logosctl call keystore_module configure '{doc}'")
}

pub fn holds(identity: &Value, me: &str, role: &str) -> bool {
    identity
        .get(role)
        .and_then(Value::as_array)
        .map(|a| a.iter().any(|v| v.as_str() == Some(me)))
        .unwrap_or(false)
}

pub fn not_custodian(hint: &str) -> String {
    format!("not authorized: keystore_cli is not a configured custodian. Run: {hint}")
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
        let id = json!({ "approvers": ["signer_ui"], "custodians": ["keystore_ui"] });
        assert_eq!(
            configure_hint(&id, "keystore_cli", "custodians"),
            r#"logosctl call keystore_module configure '{"approvers":["signer_ui"],"custodians":["keystore_ui","keystore_cli"]}'"#
        );
        let already = json!({ "approvers": [], "custodians": ["keystore_cli"] });
        assert!(configure_hint(&already, "keystore_cli", "custodians").contains(r#""custodians":["keystore_cli"]"#));
    }

    #[test]
    fn only_the_opaque_refusal_is_translated() {
        let hint = "logosctl call keystore_module configure '{}'";
        let out = translate_refusal(r#"{"ok":false,"error":"not authorized"}"#, || hint.to_string());
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["ok"], false);
        assert!(v["error"].as_str().unwrap().starts_with("not authorized: keystore_cli is not a configured custodian. Run: "));
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
        let id = json!({ "approvers": ["signer_ui"], "custodians": ["keystore_ui", "keystore_cli"] });
        assert!(holds(&id, "keystore_cli", "custodians"));
        assert!(!holds(&id, "keystore_cli", "approvers"));
    }
}
