# evm_keystore_cli

The headless custodian for `keystore_module` and `signer_manager_module` — what `evm_keystore_ui`
is in Basecamp, for a `logosctl` daemon that has no window.

Every mutation of the keystore — creating, importing, deriving, renaming, exporting and
deleting accounts — is admitted only to a configured **custodian**, and
`logosctl call keystore_module import_private_key …` is refused on purpose: the CLI is the
host anchor, not a named module. `evm_keystore_cli` is a named module. It relays every one of the
keystore's seventeen gated methods under its own identity, with the same names and the same
parameters, and turns the keystore's one opaque refusal into a sentence that names the fix.

It also decides apps' requests to the [signer manager](https://github.com/logos-co/logos-signer-manager-module)
once the manager names it a custodian: an app asks to **open** a Bitcoin wallet, and receives its
descriptors and database key, or asks for an account to stay **unlocked** on terms the person
decides. The person's own unlocks, locks and closes go through the same calls.

## A session

```bash
# once per daemon — configure is TOTAL, so restate the GUI surfaces and the signer manager alongside
logosctl call keystore_module configure '{"approvers":["evm_signer_ui","evm_signer_cli"],"custodians":["evm_keystore_ui","evm_keystore_cli"],"managers":["signer_manager_module"]}'
logosctl module load evm_keystore_cli

umask 077; printf '%s\n' 'vault password' > /run/user/501/pw
logosctl call evm_keystore_cli create_mnemonic 12
logosctl call evm_keystore_cli import_mnemonic @import.json      # {"phrase":…,"password":…,"storage":"extkey","groupPassword":…}
logosctl call evm_keystore_cli import_private_key <hex> @/run/user/501/pw
logosctl call evm_keystore_cli set_label <address> str:Treasury @/run/user/501/pw
logosctl call evm_keystore_cli list_accounts
```

Driving the wallet itself headlessly — the send that spends what is imported here — is covered in
the [logos-eth-wallet-backend README](https://github.com/logos-co/logos-eth-wallet-backend#headless-operation-logosctl),
*Headless operation*.

## Methods

Gated, one per entry of the keystore's Tier D registry: `create_mnemonic`,
`import_mnemonic`, `import_private_key`, `import_keystore_json`, `export_keystore_json`,
`change_password`, `set_label`, `set_group_label`, `delete_account`, `derive_next_account`,
`derive_account_at`, `preview_addresses`, `create_unrelated_account`, `forget_derivation`,
`remove_group`, `settle`, `remove_unexplained`. Parameters and replies are the keystore's —
see its `docs/specs.md`.

Bitcoin wallets and kept phrases, also gated: `import_bitcoin` (a phrase, a `family` and a
`chain`, optionally `keepPhrase: {password}`, or `keptPhrase` with its `phrasePassword` in place
of the phrase; `origin: "created"` for a phrase made for this wallet, or a restored wallet's
`birthday`, the day it was first used as `YYYY-MM-DD`, so an app that opens it knows where to
start looking for its coins), `show_phrase` (`{phrase, password}`) and `forget_phrase` (`{phrase}`).
A wallet whose key is on a device keeps its database key in the keystore too, made at its first open
under a password the person sets: `device_wallets` lists them, and `forget_device_wallet`
(`{signer, account}`) forgets one, the way out of a forgotten password.
`import_mnemonic` takes the same `keepPhrase`, or `keptPhrase` with its `phrasePassword`, for an
EVM wallet. Pass the documents that carry passwords as `@file`.

The signer manager's custodian methods, relayed as this module: `access_requests`,
`show_access(handle)` (the manager's `acknowledge_access`), `approve_access` (`{handle, bundle_id,
group?, password, unlock?, birthday?}`, as `@file`: a device wallet's first open sets its data
password, with the day it was first used), `reject_access(handle)`, `unlock` (`{account, password,
ttlMs?, count?, apps, confirm?}`, as `@file`), `lock` (`{account?}`, everything for `{}`),
`unlocked`, `open_accounts`, `close_account` (`{group, module}`).

Ungated, relayed so one module covers the session: `list_accounts`, `get_labels`,
`get_group_labels`, `list_groups`, `list_derivation_keys`, `get_provenance`, `list_phrases`,
`caller_identity`. And `status()` → `{ok, held, identity, approvers, custodians, hint,
manager_held, manager_hint}`: `manager_hint` is the manager's `configure` command that adds this
module to its custodians while keeping the approvers and the signers.

One deviation: `delete_account` answers `{ok}` / `{ok:false, error}` rather than the
keystore's bare `bool`. The keystore cannot tell a wrong password from a refusal there by
construction; this module knows its own standing, so it says which it was.

## Arguments

- **JSON documents** (`params_json`) are passed as one quoted string or `@file` — never with
  `json:`. The keystore takes text and parses it itself; a `json:` value is refused at the
  dispatch boundary.
- **Passwords:** `@file` (out of shell history and `ps`) or `str:…`. Never bare — `1234` is
  coerced to a number. A file written with `echo` ends in a newline; exactly one is
  stripped. Passwords *inside* a JSON document are left exactly as written.
- **Labels** that look numeric: `str:`. **Addresses:** bare hex without `0x`.

The daemon logs only the argument count of a call, never a value; this module never logs,
emits or stores a secret, and wipes its copies after each call.

**On a daemon predating the completion-channel reservation, do not
`logosctl watch evm_keystore_cli`** (or `keystore_module`) on a shared terminal: such a daemon
publishes every method reply as a `__logos_call_complete__` event on the module's channel, and
a `create_mnemonic` reply is a recovery phrase. That was a property of the platform's call
plane, not of this module, and it applied to the keystore itself equally.

logos-protocol now **reserves** that name — a subscriber cannot ask for it, and the no-filter
form of `watch` does not carry it — so a bare watch shows only the module's own events. The
change is **not** in `0.3.0-rc.1` or any earlier release, so check the daemon you actually run
rather than a version string:

```bash
logosctl watch keystore_module --json &   # then call any method
# a line carrying "event":"__logos_call_complete__" means this daemon still relays replies
```

`--event <name>` stays the right habit either way: it keeps the stream to what a human needs
and does not depend on the daemon's version.

## What is deliberately absent

- **No self-enrolment.** `configure` is ungated and total; the operator names the roles and
  `status` says what to run.
- **No events.** `logosctl watch keystore_module` already shows `accounts_changed`
  verbatim; a relay would only duplicate it.

## Build and test

```bash
nix build .#default            # the plugin
nix build .#install            # modules/evm_keystore_cli/ for a logosctl session
nix build .#lgx-portable       # an installable .lgx (the -dev variant a daemon refuses is .#lgx)
(cd rust-lib && cargo test --no-default-features)   # the Logos-free helpers
./doctests/run.sh              # the headless spec, end to end against a real daemon
```
