//! The app half of the evm_keystore_cli doc-test. It asks the signer manager to open a wallet and
//! to unlock it, keeps each receipt, and reports what it was handed; the CLI decides. Method-driven,
//! so the spec controls every step.

use serde_json::{json, Value};

type Receipts = std::sync::Mutex<std::collections::HashMap<String, String>>;

pub trait KcliProbeModule: Send + 'static {
    /// Ask to open any native segwit wallet on `network`. `{ ok, handle }`; the receipt stays here.
    fn request_open(&mut self, network: String) -> String;
    /// Ask for `account` to stay unlocked for `count` confirmed signatures of this module's.
    fn request_unlock(&mut self, account: String, count: i64) -> String;
    /// `{ ok, state, reason?, result? }`: what was handed over, once the person decided.
    fn outcome(&mut self, handle: String) -> String;
    fn on_context_ready(&mut self, _ctx: &RustModuleContext) {}
}

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/generated/provider_gen.rs"));

#[derive(Default)]
struct KcliProbeModuleImpl {
    receipts: Receipts,
}

fn err(e: impl std::fmt::Display) -> String {
    json!({ "ok": false, "error": e.to_string() }).to_string()
}

fn parse(reply: Result<String, impl std::fmt::Debug>) -> Result<Value, String> {
    let raw = reply.map_err(|e| format!("{e:?}"))?;
    let v: Value = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    if v.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(v.get("error").and_then(Value::as_str).unwrap_or("call refused").to_string());
    }
    Ok(v)
}

fn text(v: &Value, key: &str) -> String {
    v.get(key).and_then(Value::as_str).unwrap_or_default().to_string()
}

impl KcliProbeModuleImpl {
    fn keep(&self, reply: Result<Value, String>) -> String {
        match reply {
            Ok(v) => {
                let (handle, receipt) = (text(&v, "handle"), text(&v, "receipt"));
                self.receipts.lock().unwrap().insert(handle.clone(), receipt);
                json!({ "ok": true, "handle": handle }).to_string()
            }
            Err(e) => err(format!("refused: {e}")),
        }
    }
}

impl KcliProbeModule for KcliProbeModuleImpl {
    fn request_open(&mut self, network: String) -> String {
        let p = json!({ "family": "bitcoin", "network": network, "reason": "Doc-test: open a wallet headlessly" });
        self.keep(parse(modules().signer_manager_module.request_open(&p.to_string())))
    }

    fn request_unlock(&mut self, account: String, count: i64) -> String {
        let p = json!({ "account": account, "count": count, "confirm": true, "apps": ["kcli_probe"],
                        "reason": "Doc-test: a few signatures" });
        self.keep(parse(modules().signer_manager_module.request_unlock(&p.to_string())))
    }

    fn outcome(&mut self, handle: String) -> String {
        let Some(receipt) = self.receipts.lock().unwrap().get(&handle).cloned() else {
            return err("no receipt for that handle");
        };
        let status = match parse(modules().signer_manager_module.approval_status(&handle, &receipt)) {
            Ok(v) => v,
            Err(e) => return err(format!("approval_status: {e}")),
        };
        let (state, reason) = (text(&status, "state"), text(&status, "reason"));
        if reason != "approved" {
            return json!({ "ok": true, "state": state, "reason": reason }).to_string();
        }
        match parse(modules().signer_manager_module.fetch_result(&handle, &receipt)) {
            Ok(v) => {
                let _ = modules().signer_manager_module.ack_result(&handle, &receipt);
                json!({ "ok": true, "state": state, "reason": reason, "result": v.get("result").cloned() }).to_string()
            }
            Err(e) => err(format!("fetch_result: {e}")),
        }
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<KcliProbeModuleImpl>();
}
