//! Logos glue for `evm_keystore_cli`: every Tier D method of `keystore_module`, and the signer
//! manager's custodian methods, relayed under this module's identity so a headless operator can
//! hold both custodian roles.

use crate::relay::{
    configure_hint, holds, manager_configure_hint, not_custodian, scrub, strip_file_newline, translate_manager_refusal,
    translate_refusal,
};
use serde_json::{json, Value};

const ME: &str = "evm_keystore_cli";

pub trait EvmKeystoreCliModule: Send + 'static {
    /// `{ ok, held, identity, approvers, custodians, hint, manager_held, manager_hint }`.
    fn status(&mut self) -> String;

    // Tier D — admitted only once `configure` names evm_keystore_cli a custodian.
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
    /// A Bitcoin wallet from a phrase, or from a kept one; keeps the phrase when asked.
    fn import_bitcoin(&mut self, params_json: String) -> String;
    /// A kept phrase's words: `{ phrase, password }`.
    fn show_phrase(&mut self, params_json: String) -> String;
    /// `{ phrase }`: remove a kept phrase.
    fn forget_phrase(&mut self, params_json: String) -> String;

    // The signer manager's custodian: apps' open and unlock requests, and the person's own unlocks.
    /// The requests waiting: `{ ok, requests: [{ handle, requester, kind, state, ageMs }] }`.
    fn access_requests(&mut self) -> String;
    /// Claim one for display: its lines, the commitment to echo, and what was asked.
    fn show_access(&mut self, handle: String) -> String;
    /// Decide it: `{ handle, bundle_id, group?, password, unlock? }`, as a file.
    fn approve_access(&mut self, params_json: String) -> String;
    fn reject_access(&mut self, handle: String) -> String;
    /// The person's own unlock: `{ account, password, ttlMs?, count?, apps, confirm? }`, as a file.
    fn unlock(&mut self, params_json: String) -> String;
    /// `{ account? }`, everything for `{}`.
    fn lock(&mut self, params_json: String) -> String;
    fn unlocked(&mut self) -> String;
    fn open_accounts(&mut self) -> String;
    /// `{ group, module }`: close a wallet opened for an app.
    fn close_account(&mut self, params_json: String) -> String;

    // Ungated reads, relayed so one module covers the whole headless session.
    fn list_phrases(&mut self) -> String;
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
struct EvmKeystoreCliModuleImpl;

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

fn manager_identity() -> Value {
    modules()
        .signer_manager_module
        .caller_identity()
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(Value::Null)
}

fn relay_manager(reply: Result<String, impl std::fmt::Debug>) -> String {
    match reply {
        Ok(s) => translate_manager_refusal(&s, || manager_configure_hint(&manager_identity(), ME)),
        Err(e) => json!({ "ok": false, "error": format!("signer manager unreachable: {e:?}") }).to_string(),
    }
}

/// A document carrying a password, relayed and then wiped.
fn with_secret_doc(mut doc: String, f: impl FnOnce(&str) -> String) -> String {
    let out = f(strip_file_newline(&doc));
    scrub(&mut doc);
    out
}

/// Run `f` on the password as the operator meant it, then wipe the copy we hold.
fn with_secret<T>(secret: &mut String, f: impl FnOnce(&str) -> T) -> T {
    let out = f(strip_file_newline(secret));
    scrub(secret);
    out
}

impl EvmKeystoreCliModule for EvmKeystoreCliModuleImpl {
    fn status(&mut self) -> String {
        let id = identity();
        let mid = manager_identity();
        let held = holds(&id, ME, "custodians");
        json!({
            "ok": true,
            "held": held,
            "identity": id.get("identity").cloned().unwrap_or(Value::Null),
            "approvers": id.get("approvers").cloned().unwrap_or(json!([])),
            "custodians": id.get("custodians").cloned().unwrap_or(json!([])),
            "hint": if held { Value::Null } else { Value::String(configure_hint(&id, ME, "custodians")) },
            "manager_held": holds(&mid, ME, "custodians"),
            "manager_hint": if holds(&mid, ME, "custodians") { Value::Null }
                            else { Value::String(manager_configure_hint(&mid, ME)) },
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

    fn import_bitcoin(&mut self, params_json: String) -> String {
        with_secret_doc(params_json, |doc| relay(modules().keystore_module.import_bitcoin(doc)))
    }
    fn show_phrase(&mut self, params_json: String) -> String {
        with_secret_doc(params_json, |doc| relay(modules().keystore_module.show_phrase(doc)))
    }
    fn forget_phrase(&mut self, params_json: String) -> String {
        relay(modules().keystore_module.forget_phrase(strip_file_newline(&params_json)))
    }

    fn access_requests(&mut self) -> String {
        relay_manager(modules().signer_manager_module.access_requests())
    }
    fn show_access(&mut self, handle: String) -> String {
        relay_manager(modules().signer_manager_module.acknowledge_access(handle.trim()))
    }
    fn approve_access(&mut self, params_json: String) -> String {
        with_secret_doc(params_json, |doc| relay_manager(modules().signer_manager_module.approve_access(doc)))
    }
    fn reject_access(&mut self, handle: String) -> String {
        match modules().signer_manager_module.reject_access(handle.trim()) {
            Ok(true) => json!({ "ok": true }).to_string(),
            Ok(false) => json!({ "ok": false, "error": "reject refused: not the custodian, or no such request" }).to_string(),
            Err(e) => json!({ "ok": false, "error": format!("signer manager unreachable: {e:?}") }).to_string(),
        }
    }
    fn unlock(&mut self, params_json: String) -> String {
        with_secret_doc(params_json, |doc| relay_manager(modules().signer_manager_module.unlock(doc)))
    }
    fn lock(&mut self, params_json: String) -> String {
        relay_manager(modules().signer_manager_module.lock(strip_file_newline(&params_json)))
    }
    fn unlocked(&mut self) -> String {
        relay_manager(modules().signer_manager_module.unlocked())
    }
    fn open_accounts(&mut self) -> String {
        relay_manager(modules().signer_manager_module.open_accounts())
    }
    fn close_account(&mut self, params_json: String) -> String {
        relay_manager(modules().signer_manager_module.close_account(strip_file_newline(&params_json)))
    }

    fn list_phrases(&mut self) -> String {
        relay(modules().keystore_module.list_phrases())
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
    install::<EvmKeystoreCliModuleImpl>();
}
