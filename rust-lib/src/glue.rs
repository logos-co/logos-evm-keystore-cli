//! Logos glue for `evm_keystore_cli`: every Tier D method of `keystore_module`, and the signer
//! manager's custodian methods, relayed under this module's identity so a headless operator can
//! hold both custodian roles.

use crate::relay::{
    configure_hint, holds, manager_configure_hint, not_custodian, scrub, strip_file_newline, translate_manager_refusal,
    translate_refusal,
};
use serde_json::{json, Value};

const ME: &str = "evm_keystore_cli";

pub trait EvmKeystoreCliModule: Send + Sync + 'static {
    /// `{ ok, held, identity, approvers, custodians, hint, manager_held, manager_hint }`.
    fn status(&self) -> String;

    // Tier D — admitted only once `configure` names evm_keystore_cli a custodian.
    fn create_mnemonic(&self, words: i64) -> String;
    fn import_mnemonic(&self, params_json: String) -> String;
    fn derive_next_account(&self, params_json: String) -> String;
    fn derive_account_at(&self, params_json: String) -> String;
    fn preview_addresses(&self, params_json: String) -> String;
    fn create_unrelated_account(&self, params_json: String) -> String;
    fn forget_derivation(&self, params_json: String) -> String;
    fn remove_group(&self, params_json: String) -> String;
    fn settle(&self) -> String;
    fn remove_unexplained(&self, params_json: String) -> String;
    fn set_group_label(&self, params_json: String) -> String;
    fn import_private_key(&self, priv_hex: String, password: String) -> String;
    fn import_keystore_json(&self, key_json: String, password: String, new_password: String) -> String;
    fn export_keystore_json(&self, address: String, password: String) -> String;
    /// `{ ok }` rather than the keystore's bare bool, so a refusal can say why.
    fn delete_account(&self, address: String, password: String) -> String;
    fn change_password(&self, address: String, old_password: String, new_password: String) -> String;
    fn set_label(&self, address: String, label: String, password: String) -> String;
    /// A Bitcoin wallet from a phrase, or from a kept one; keeps the phrase when asked.
    fn import_bitcoin(&self, params_json: String) -> String;
    /// A kept phrase's words: `{ phrase, password }`.
    fn show_phrase(&self, params_json: String) -> String;
    /// `{ phrase }`: remove a kept phrase.
    fn forget_phrase(&self, params_json: String) -> String;
    /// The device accounts whose wallet has a database key in the keystore.
    fn device_wallets(&self) -> String;
    /// `{ signer, account }`: forget a device wallet's database key, the way out of a forgotten password.
    fn forget_device_wallet(&self, params_json: String) -> String;
    /// Move in what an older build left in `keystore/`: `{ ok, accounts, keys, phrases, devices,
    /// documents, left }` of what moved, `left` being what stays.
    fn move_older_keystore(&self) -> String;

    // The signer manager's custodian: apps' open and unlock requests, and the person's own unlocks.
    /// The requests waiting: `{ ok, requests: [{ handle, requester, kind, state, ageMs }] }`.
    fn access_requests(&self) -> String;
    /// Claim one for display: its lines, the commitment to echo, and what was asked.
    fn show_access(&self, handle: String) -> String;
    /// Decide it: `{ handle, bundle_id, group?, password, unlock?, birthday? }`, as a file; a device
    /// wallet's first open sets its data password, with the day it was first used.
    fn approve_access(&self, params_json: String) -> String;
    fn reject_access(&self, handle: String) -> String;
    /// The person's own unlock: `{ account, password, ttlMs?, count?, apps, confirm? }`, as a file.
    fn unlock(&self, params_json: String) -> String;
    /// `{ account? }`, everything for `{}`.
    fn lock(&self, params_json: String) -> String;
    fn unlocked(&self) -> String;
    fn open_accounts(&self) -> String;
    /// `{ group, module }`: close a wallet opened for an app.
    fn close_account(&self, params_json: String) -> String;

    // Ungated reads, relayed so one module covers the whole headless session.
    fn list_phrases(&self) -> String;
    fn list_accounts(&self) -> String;
    fn get_labels(&self) -> String;
    fn get_group_labels(&self) -> String;
    fn list_groups(&self) -> String;
    fn list_derivation_keys(&self) -> String;
    fn get_provenance(&self) -> String;
    /// What `move_older_keystore` would move, in the same shape.
    fn older_keystore(&self) -> String;
    fn caller_identity(&self) -> String;

    fn on_context_ready(&self, _ctx: &RustModuleContext) {}
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
    fn status(&self) -> String {
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

    fn create_mnemonic(&self, words: i64) -> String {
        relay(modules().keystore_module.create_mnemonic(words))
    }
    fn import_mnemonic(&self, params_json: String) -> String {
        relay(modules().keystore_module.import_mnemonic(&params_json))
    }
    fn derive_next_account(&self, params_json: String) -> String {
        relay(modules().keystore_module.derive_next_account(&params_json))
    }
    fn derive_account_at(&self, params_json: String) -> String {
        relay(modules().keystore_module.derive_account_at(&params_json))
    }
    fn preview_addresses(&self, params_json: String) -> String {
        relay(modules().keystore_module.preview_addresses(&params_json))
    }
    fn create_unrelated_account(&self, params_json: String) -> String {
        relay(modules().keystore_module.create_unrelated_account(&params_json))
    }
    fn forget_derivation(&self, params_json: String) -> String {
        relay(modules().keystore_module.forget_derivation(&params_json))
    }
    fn remove_group(&self, params_json: String) -> String {
        relay(modules().keystore_module.remove_group(&params_json))
    }
    fn settle(&self) -> String {
        relay(modules().keystore_module.settle())
    }
    fn remove_unexplained(&self, params_json: String) -> String {
        relay(modules().keystore_module.remove_unexplained(&params_json))
    }
    fn set_group_label(&self, params_json: String) -> String {
        relay(modules().keystore_module.set_group_label(&params_json))
    }

    fn import_private_key(&self, mut priv_hex: String, mut password: String) -> String {
        let out = with_secret(&mut password, |pw| {
            relay(modules().keystore_module.import_private_key(strip_file_newline(&priv_hex), pw))
        });
        scrub(&mut priv_hex);
        out
    }
    fn import_keystore_json(&self, mut key_json: String, mut password: String, mut new_password: String) -> String {
        let out = with_secret(&mut password, |pw| {
            with_secret(&mut new_password, |npw| {
                relay(modules().keystore_module.import_keystore_json(&key_json, pw, npw))
            })
        });
        scrub(&mut key_json);
        out
    }
    fn export_keystore_json(&self, address: String, mut password: String) -> String {
        with_secret(&mut password, |pw| relay(modules().keystore_module.export_keystore_json(&address, pw)))
    }
    fn delete_account(&self, address: String, mut password: String) -> String {
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
    fn change_password(&self, address: String, mut old_password: String, mut new_password: String) -> String {
        with_secret(&mut old_password, |old| {
            with_secret(&mut new_password, |new| {
                relay(modules().keystore_module.change_password(&address, old, new))
            })
        })
    }
    fn set_label(&self, address: String, label: String, mut password: String) -> String {
        with_secret(&mut password, |pw| relay(modules().keystore_module.set_label(&address, &label, pw)))
    }

    fn import_bitcoin(&self, params_json: String) -> String {
        with_secret_doc(params_json, |doc| relay(modules().keystore_module.import_bitcoin(doc)))
    }
    fn show_phrase(&self, params_json: String) -> String {
        with_secret_doc(params_json, |doc| relay(modules().keystore_module.show_phrase(doc)))
    }
    fn forget_phrase(&self, params_json: String) -> String {
        relay(modules().keystore_module.forget_phrase(strip_file_newline(&params_json)))
    }
    fn device_wallets(&self) -> String {
        relay(modules().keystore_module.device_wallets())
    }
    fn forget_device_wallet(&self, params_json: String) -> String {
        relay(modules().keystore_module.forget_device_wallet(strip_file_newline(&params_json)))
    }
    fn move_older_keystore(&self) -> String {
        relay(modules().keystore_module.move_older_keystore())
    }

    fn access_requests(&self) -> String {
        relay_manager(modules().signer_manager_module.access_requests())
    }
    fn show_access(&self, handle: String) -> String {
        relay_manager(modules().signer_manager_module.acknowledge_access(handle.trim()))
    }
    fn approve_access(&self, params_json: String) -> String {
        with_secret_doc(params_json, |doc| relay_manager(modules().signer_manager_module.approve_access(doc)))
    }
    fn reject_access(&self, handle: String) -> String {
        match modules().signer_manager_module.reject_access(handle.trim()) {
            Ok(true) => json!({ "ok": true }).to_string(),
            Ok(false) => json!({ "ok": false, "error": "reject refused: not the custodian, or no such request" }).to_string(),
            Err(e) => json!({ "ok": false, "error": format!("signer manager unreachable: {e:?}") }).to_string(),
        }
    }
    fn unlock(&self, params_json: String) -> String {
        with_secret_doc(params_json, |doc| relay_manager(modules().signer_manager_module.unlock(doc)))
    }
    fn lock(&self, params_json: String) -> String {
        relay_manager(modules().signer_manager_module.lock(strip_file_newline(&params_json)))
    }
    fn unlocked(&self) -> String {
        relay_manager(modules().signer_manager_module.unlocked())
    }
    fn open_accounts(&self) -> String {
        relay_manager(modules().signer_manager_module.open_accounts())
    }
    fn close_account(&self, params_json: String) -> String {
        relay_manager(modules().signer_manager_module.close_account(strip_file_newline(&params_json)))
    }

    fn list_phrases(&self) -> String {
        relay(modules().keystore_module.list_phrases())
    }
    fn list_accounts(&self) -> String {
        relay(modules().keystore_module.list_accounts())
    }
    fn get_labels(&self) -> String {
        relay(modules().keystore_module.get_labels())
    }
    fn get_group_labels(&self) -> String {
        relay(modules().keystore_module.get_group_labels())
    }
    fn list_groups(&self) -> String {
        relay(modules().keystore_module.list_groups())
    }
    fn list_derivation_keys(&self) -> String {
        relay(modules().keystore_module.list_derivation_keys())
    }
    fn get_provenance(&self) -> String {
        relay(modules().keystore_module.get_provenance())
    }
    fn older_keystore(&self) -> String {
        relay(modules().keystore_module.older_keystore())
    }
    fn caller_identity(&self) -> String {
        relay(modules().keystore_module.caller_identity())
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<EvmKeystoreCliModuleImpl>();
}
