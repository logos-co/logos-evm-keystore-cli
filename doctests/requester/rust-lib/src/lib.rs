//! kcli_probe — the evm_keystore_cli doc-test's app: it asks the signer manager to open a wallet
//! and to unlock it, and reports what it was handed. The CLI decides, as the manager's custodian.
#[cfg(feature = "logos_module")]
mod glue;
