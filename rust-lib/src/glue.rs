//! Logos glue for `keystore_cli`: every Tier D method of `keystore_module`, relayed
//! under this module's identity so a headless operator can hold the custodian role.

use crate::relay::{configure_hint, holds, not_custodian, scrub, strip_file_newline, translate_refusal};
use serde_json::{json, Value};

const ME: &str = "keystore_cli";

pub trait KeystoreCliModule: Send + 'static {
    /// `{ ok, held, identity, approvers, custodians, hint }`.
    fn status(&mut self) -> String;

    // Tier D — admitted only once `configure` names keystore_cli a custodian.
    fn create_mnemonic(&mut self, words: i64) -> String;
    fn import_mnemonic(&mut self, params_json: String) -> String;
    fn derive_next_account(&mut self, params_json: String) -> String;
    fn derive_account_at(&mut self, params_json: String) -> String;
    fn preview_addresses(&mut self, params_json: String) -> String;
    fn create_unrelated_account(&mut self, params_json: String) -> String;
    fn forget_derivation(&mut self, params_json: String) -> String;
    fn remove_group(&mut self, params_json: String) -> String;
    fn settle(&mut self) -> String;
    fn remove_unexplained(&mut self, params_json: String) -> String;
    fn set_group_label(&mut self, params_json: String) -> String;
    fn import_private_key(&mut self, priv_hex: String, password: String) -> String;
    fn import_keystore_json(&mut self, key_json: String, password: String, new_password: String) -> String;
    fn export_keystore_json(&mut self, address: String, password: String) -> String;
    /// `{ ok }` rather than the keystore's bare bool, so a refusal can say why.
    fn delete_account(&mut self, address: String, password: String) -> String;
    fn change_password(&mut self, address: String, old_password: String, new_password: String) -> String;
    fn set_label(&mut self, address: String, label: String, password: String) -> String;

    // Ungated reads, relayed so one module covers the whole headless session.
    fn list_accounts(&mut self) -> String;
    fn get_labels(&mut self) -> String;
    fn get_group_labels(&mut self) -> String;
    fn list_groups(&mut self) -> String;
    fn list_derivation_keys(&mut self) -> String;
    fn get_provenance(&mut self) -> String;
    fn caller_identity(&mut self) -> String;

    fn on_context_ready(&mut self, _ctx: &RustModuleContext) {}
}

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/generated/provider_gen.rs"));

#[derive(Default)]
struct KeystoreCliModuleImpl;

fn unreachable(e: impl std::fmt::Debug) -> String {
    json!({ "ok": false, "error": format!("keystore unreachable: {e:?}") }).to_string()
}

fn identity() -> Value {
    modules()
        .keystore_module
        .caller_identity()
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(Value::Null)
}

fn hint() -> String {
    configure_hint(&identity(), ME, "custodians")
}

fn relay(reply: Result<String, impl std::fmt::Debug>) -> String {
    match reply {
        Ok(s) => translate_refusal(&s, hint),
        Err(e) => unreachable(e),
    }
}

/// Run `f` on the password as the operator meant it, then wipe the copy we hold.
fn with_secret<T>(secret: &mut String, f: impl FnOnce(&str) -> T) -> T {
    let out = f(strip_file_newline(secret));
    scrub(secret);
    out
}

impl KeystoreCliModule for KeystoreCliModuleImpl {
    fn status(&mut self) -> String {
        let id = identity();
        let held = holds(&id, ME, "custodians");
        json!({
            "ok": true,
            "held": held,
            "identity": id.get("identity").cloned().unwrap_or(Value::Null),
            "approvers": id.get("approvers").cloned().unwrap_or(json!([])),
            "custodians": id.get("custodians").cloned().unwrap_or(json!([])),
            "hint": if held { Value::Null } else { Value::String(configure_hint(&id, ME, "custodians")) },
        })
        .to_string()
    }

    fn create_mnemonic(&mut self, words: i64) -> String {
        relay(modules().keystore_module.create_mnemonic(words))
    }
    fn import_mnemonic(&mut self, params_json: String) -> String {
        relay(modules().keystore_module.import_mnemonic(&params_json))
    }
    fn derive_next_account(&mut self, params_json: String) -> String {
        relay(modules().keystore_module.derive_next_account(&params_json))
    }
    fn derive_account_at(&mut self, params_json: String) -> String {
        relay(modules().keystore_module.derive_account_at(&params_json))
    }
    fn preview_addresses(&mut self, params_json: String) -> String {
        relay(modules().keystore_module.preview_addresses(&params_json))
    }
    fn create_unrelated_account(&mut self, params_json: String) -> String {
        relay(modules().keystore_module.create_unrelated_account(&params_json))
    }
    fn forget_derivation(&mut self, params_json: String) -> String {
        relay(modules().keystore_module.forget_derivation(&params_json))
    }
    fn remove_group(&mut self, params_json: String) -> String {
        relay(modules().keystore_module.remove_group(&params_json))
    }
    fn settle(&mut self) -> String {
        relay(modules().keystore_module.settle())
    }
    fn remove_unexplained(&mut self, params_json: String) -> String {
        relay(modules().keystore_module.remove_unexplained(&params_json))
    }
    fn set_group_label(&mut self, params_json: String) -> String {
        relay(modules().keystore_module.set_group_label(&params_json))
    }

    fn import_private_key(&mut self, mut priv_hex: String, mut password: String) -> String {
        let out = with_secret(&mut password, |pw| {
            relay(modules().keystore_module.import_private_key(strip_file_newline(&priv_hex), pw))
        });
        scrub(&mut priv_hex);
        out
    }
    fn import_keystore_json(&mut self, mut key_json: String, mut password: String, mut new_password: String) -> String {
        let out = with_secret(&mut password, |pw| {
            with_secret(&mut new_password, |npw| {
                relay(modules().keystore_module.import_keystore_json(&key_json, pw, npw))
            })
        });
        scrub(&mut key_json);
        out
    }
    fn export_keystore_json(&mut self, address: String, mut password: String) -> String {
        with_secret(&mut password, |pw| relay(modules().keystore_module.export_keystore_json(&address, pw)))
    }
    fn delete_account(&mut self, address: String, mut password: String) -> String {
        let out = with_secret(&mut password, |pw| modules().keystore_module.delete_account(&address, pw));
        match out {
            Ok(true) => json!({ "ok": true }).to_string(),
            Ok(false) if holds(&identity(), ME, "custodians") => {
                json!({ "ok": false, "error": "delete refused: wrong password, or no such account" }).to_string()
            }
            Ok(false) => json!({ "ok": false, "error": not_custodian(&hint()) }).to_string(),
            Err(e) => unreachable(e),
        }
    }
    fn change_password(&mut self, address: String, mut old_password: String, mut new_password: String) -> String {
        with_secret(&mut old_password, |old| {
            with_secret(&mut new_password, |new| {
                relay(modules().keystore_module.change_password(&address, old, new))
            })
        })
    }
    fn set_label(&mut self, address: String, label: String, mut password: String) -> String {
        with_secret(&mut password, |pw| relay(modules().keystore_module.set_label(&address, &label, pw)))
    }

    fn list_accounts(&mut self) -> String {
        relay(modules().keystore_module.list_accounts())
    }
    fn get_labels(&mut self) -> String {
        relay(modules().keystore_module.get_labels())
    }
    fn get_group_labels(&mut self) -> String {
        relay(modules().keystore_module.get_group_labels())
    }
    fn list_groups(&mut self) -> String {
        relay(modules().keystore_module.list_groups())
    }
    fn list_derivation_keys(&mut self) -> String {
        relay(modules().keystore_module.list_derivation_keys())
    }
    fn get_provenance(&mut self) -> String {
        relay(modules().keystore_module.get_provenance())
    }
    fn caller_identity(&mut self) -> String {
        relay(modules().keystore_module.caller_identity())
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<KeystoreCliModuleImpl>();
}
