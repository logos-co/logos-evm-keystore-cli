//! evm_keystore_cli — the headless custodian for `keystore_module`.

pub mod relay;

#[cfg(feature = "logos_module")]
mod glue;
