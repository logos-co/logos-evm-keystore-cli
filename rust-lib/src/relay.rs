//! Logos-free helpers: argument normalisation and refusal translation.

use serde_json::{json, Value};

/// Drop exactly one trailing newline: `@file` hands over the file verbatim, and a
/// password file written with `echo` ends in one.
pub fn strip_file_newline(s: &str) -> &str {
    s.strip_suffix("\r\n").or_else(|| s.strip_suffix('\n')).unwrap_or(s)
}

/// Every keystore method this module relays, and so the list the deployer's access policy
/// grants it at `keystore_module`. A list: a `"*"` grant is not scoped, and the keystore
/// admits Tier D only on a scoped call or from its built-in custodian.
pub const KEYSTORE_METHODS: &[&str] = &[
    "create_mnemonic", "import_mnemonic", "import_private_key", "import_keystore_json",
    "export_keystore_json", "change_password", "set_label", "set_group_label", "delete_account",
    "derive_next_account", "derive_account_at", "preview_addresses", "create_unrelated_account",
    "forget_derivation", "remove_group", "settle", "remove_unexplained",
    "list_accounts", "get_labels", "get_group_labels", "list_groups", "list_derivation_keys",
    "get_provenance", "caller_identity",
];

/// The access policy granting `me` its `methods` at keystore_module, which leaves every other
/// caller, operators included, to the keystore's own roles. With a keystore_module rule of
/// your own, add only the `me` entry.
pub fn policy_hint(me: &str, methods: &[&str]) -> String {
    let mut callers = serde_json::Map::new();
    callers.insert(me.to_string(), json!(methods));
    callers.insert("*".to_string(), json!("*"));
    callers.insert("@op:*".to_string(), json!("*"));
    let doc = json!({ "version": 2, "mode": "explicit",
                      "restrictions": { "keystore_module": { "allowedCallers": Value::Object(callers) } } });
    format!("grant it in the daemon's access_policy and restart the daemon: {doc}")
}

/// Whether the keystore admits `me` in `role`: the runtime checked its call against a method
/// list the policy grants it (`scoped`), or it is the keystore's built-in holder of `role`.
pub fn holds(identity: &Value, me: &str, role: &str) -> bool {
    identity.get("scoped").and_then(Value::as_bool) == Some(true)
        || identity
            .get(role)
            .and_then(Value::as_array)
            .map(|a| a.iter().any(|v| v.as_str() == Some(me)))
            .unwrap_or(false)
}

pub fn not_custodian(hint: &str) -> String {
    format!("not authorized: evm_keystore_cli is not granted the custodian's methods; {hint}")
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
    fn the_hint_is_a_policy_granting_every_relayed_method() {
        let hint = policy_hint("evm_keystore_cli", KEYSTORE_METHODS);
        let doc: Value = serde_json::from_str(&hint[hint.find('{').unwrap()..]).unwrap();
        assert_eq!(doc["version"], 2);
        assert_eq!(doc["mode"], "explicit");
        let callers = &doc["restrictions"]["keystore_module"]["allowedCallers"];
        assert_eq!(callers["evm_keystore_cli"], json!(KEYSTORE_METHODS));
        assert_eq!(callers["*"], "*");
        assert_eq!(callers["@op:*"], "*");
        assert_eq!(callers.as_object().unwrap().len(), 3);
    }

    #[test]
    fn the_grant_names_every_gated_method_once() {
        for m in ["create_mnemonic", "import_mnemonic", "import_private_key", "import_keystore_json",
                  "export_keystore_json", "change_password", "set_label", "set_group_label",
                  "delete_account", "derive_next_account", "derive_account_at", "preview_addresses",
                  "create_unrelated_account", "forget_derivation", "remove_group", "settle",
                  "remove_unexplained", "caller_identity"] {
            assert!(KEYSTORE_METHODS.contains(&m), "{m} missing");
        }
        let mut sorted = KEYSTORE_METHODS.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), KEYSTORE_METHODS.len());
    }

    #[test]
    fn only_the_opaque_refusal_is_translated() {
        let hint = "grant it in the daemon's access_policy and restart the daemon: {}";
        let out = translate_refusal(r#"{"ok":false,"error":"not authorized"}"#, || hint.to_string());
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["ok"], false);
        assert!(v["error"].as_str().unwrap().starts_with("not authorized: evm_keystore_cli is not granted the custodian's methods; "));
        assert!(v["error"].as_str().unwrap().ends_with(hint));

        let other = r#"{"ok":false,"error":"word count must be 12/15/18/21/24, got 13"}"#;
        let never = || panic!("hint computed for a reply that needs none");
        assert_eq!(translate_refusal(other, never), other);
        let good = r#"{"ok":true,"phrase":"a b c"}"#;
        assert_eq!(translate_refusal(good, never), good);
        assert_eq!(translate_refusal("garbage", never), "garbage");
    }

    #[test]
    fn holds_is_a_scoped_call_or_the_built_in_role() {
        let scoped = json!({ "scoped": true, "custodians": ["evm_keystore_ui"] });
        assert!(holds(&scoped, "evm_keystore_cli", "custodians"));
        let unscoped = json!({ "scoped": false, "custodians": ["evm_keystore_ui"] });
        assert!(!holds(&unscoped, "evm_keystore_cli", "custodians"));
        assert!(holds(&unscoped, "evm_keystore_ui", "custodians"));
        assert!(!holds(&unscoped, "evm_keystore_ui", "approvers"));
        assert!(!holds(&Value::Null, "evm_keystore_cli", "custodians"));
    }
}
