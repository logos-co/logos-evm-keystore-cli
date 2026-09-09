# keystore_cli

The headless custodian for `keystore_module` — what `keystore_ui` is in Basecamp, for a
`logosctl` daemon that has no window.

Every mutation of the keystore — creating, importing, deriving, renaming, exporting and
deleting accounts — is admitted only to a configured **custodian**, and
`logosctl call keystore_module import_private_key …` is refused on purpose: the CLI is the
host anchor, not a named module. `keystore_cli` is a named module. It relays every one of the
keystore's seventeen gated methods under its own identity, with the same names and the same
parameters, and turns the keystore's one opaque refusal into a sentence that names the fix.

## A session

```bash
# once per daemon — configure is TOTAL, so restate the GUI surfaces alongside
logosctl call keystore_module configure '{"approvers":["signer_ui","signer_cli"],"custodians":["keystore_ui","keystore_cli"]}'
logosctl module load keystore_cli

umask 077; printf '%s\n' 'vault password' > /run/user/501/pw
logosctl call keystore_cli create_mnemonic 12
logosctl call keystore_cli import_mnemonic @import.json      # {"phrase":…,"password":…,"storage":"extkey","groupPassword":…}
logosctl call keystore_cli import_private_key <hex> @/run/user/501/pw
logosctl call keystore_cli set_label <address> str:Treasury @/run/user/501/pw
logosctl call keystore_cli list_accounts
```

## Methods

Gated, one per entry of the keystore's Tier D registry: `create_mnemonic`,
`import_mnemonic`, `import_private_key`, `import_keystore_json`, `export_keystore_json`,
`change_password`, `set_label`, `set_group_label`, `delete_account`, `derive_next_account`,
`derive_account_at`, `preview_addresses`, `create_unrelated_account`, `forget_derivation`,
`remove_group`, `settle`, `remove_unexplained`. Parameters and replies are the keystore's —
see its `docs/specs.md`.

Ungated, relayed so one module covers the session: `list_accounts`, `get_labels`,
`get_group_labels`, `list_groups`, `list_derivation_keys`, `get_provenance`,
`caller_identity`. And `status()` → `{ok, held, identity, approvers, custodians, hint}`.

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

**Do not `logosctl watch keystore_cli`** (or `keystore_module`) on a shared terminal: the daemon
publishes every method reply as a `__logos_call_complete__` event on the module's channel, and
a `create_mnemonic` reply is a recovery phrase. This is a property of the platform's call
plane, not of this module; it applies to the keystore itself equally.

## What is deliberately absent

- **No self-enrolment.** `configure` is ungated and total; the operator names the roles and
  `status` says what to run.
- **No events.** `logosctl watch keystore_module` already shows `accounts_changed`
  verbatim; a relay would only duplicate it.

## Build and test

```bash
nix build .#default            # the plugin
nix build .#install            # modules/keystore_cli/ for a logosctl session
nix build .#lgx-portable       # an installable .lgx (the -dev variant a daemon refuses is .#lgx)
(cd rust-lib && cargo test --no-default-features)   # the Logos-free helpers
./doctests/run.sh              # the headless spec, end to end against a real daemon
```
