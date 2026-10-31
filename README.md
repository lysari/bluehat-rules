# bluehat-rules

Detection rules for the Bluehat macOS menu bar scanner.

The app downloads only `rules.signed.json` from this repository and rejects it unless it is signed by one of the owner's Ed25519 keys, whose public halves are built into the app. Rules are data only: each rule picks one of the check types the app has built in, so nothing in this repository can make the app run code.

## Update the rules

1. Edit `rules.json`.
2. Raise `version` (format `YYYYMMDDNN`). The app refuses a version lower than the last one it verified.
3. Sign: `devbox run sign-rules` from the Bluehat project. The signer adds a signed `issued` time to the published copy; don't put it in `rules.json` yourself.
4. Commit and push both `rules.json` and `rules.signed.json`.

Sign and push at least every 14 days, even with no rule changes (raise `version`). The signer stamps `issued` and `expires` (30 days later) into the signed copy. The app warns 14 days after signing and refuses expired rules, so someone who blocks updates or keeps serving an old signed file can't freeze your rules, and the app refuses versions below its built-in minimum, so old signed files without an expiry can't be replayed to a fresh install.

## Checks on every push

`.github/workflows/verify.yml` runs `.github/scripts/verify_rules.py` (Python standard library and OpenSSL only). It fails when `rules.signed.json` isn't signed by a trusted key, doesn't match `rules.json`, has no `issued`/`expires`, has expired, has duplicate ids, or changed without a higher `version`. Its `TRUSTED_KEYS` must list the same public keys as the app's `RuleFeed.trustedKeys`. It is a consistency check, not the security boundary: the app verifies everything itself.

## Signing keys

- Primary key: in the owner's login Keychain (service `bluehat-rules-signing`), created with `bluehat-sign keygen`.
- Current trusted keys: primary `07:50:0B:8A:44:2C:EE:F7` (Keychain), backup `45:F7:3C:B2:FC:D3:CE:3E` (offline).
- Backup key: create one offline with `bluehat-sign backup-keygen /Volumes/<encrypted drive>/bluehat-backup.key`, add its public key to `RuleFeed.trustedKeys` and to `TRUSTED_KEYS` in the workflow, rebuild and reinstall the app. Keep the file off this Mac and out of git.
- Primary key lost: sign with `bluehat-sign sign rules/rules.json --key-file <backup file>`, then create a new Keychain key and add it as above.
- Primary key leaked: remove its public key from `RuleFeed.trustedKeys` and `TRUSTED_KEYS`, sign with the backup key, rebuild and reinstall the app, then create a new key and a new backup.

## Rule format

| Field | Values |
|---|---|
| `id` | lowercase letters, digits, `.` and `-`, unique |
| `title` | 1-120 characters |
| `severity` | `info`, `low`, `medium`, `high`, `critical` |
| `category` | `malware`, `rce`, `worm`, `backdoor`, `persistence`, `miner`, `hardening` |
| `check` | one of the check types below |
| `summary` | optional, up to 600 characters: why the finding matters (the app has a default per category) |
| `remedy` | optional, up to 600 characters: how to fix it (the app has a default per check type) |
| `references` | optional, up to 5 `https` links to source reports |

| `check` | Needs | Looks at |
|---|---|---|
| `path` | `paths` (start with `/` or `~/`) | files that must not exist |
| `launchItem` | `patterns` (regex) | program and arguments of LaunchAgents and LaunchDaemons, and the plist's path |
| `shellProfile` | `patterns` | lines of `~/.zshrc`, `~/.zprofile`, `~/.bashrc` and other shell startup files |
| `process` | `patterns` | command lines of running processes |
| `crontab` | `patterns` | lines of the user's crontab |
| `listeningPort` | `ports` | TCP ports with a listening process |
| `fileHash` | `hashes` (lowercase SHA-256) | files in Downloads, Desktop, `/Users/Shared` and `/private/tmp` |
| `setting` | `setting`: `sip`, `gatekeeper`, `firewall` | macOS protections that are switched off |
| `launchItemSignature` | nothing | programs started by LaunchAgents and LaunchDaemons that are unsigned, ad-hoc signed or tampered (every architecture checked) |
| `appSignature` | nothing | apps in `/Applications`, `~/Applications` and `~/Downloads` (and one folder down) that are unsigned, ad-hoc signed or changed after signing |

| `sshKey` | optional `patterns` | keys in `~/.ssh/authorized_keys` and `authorized_keys2`; without patterns every key is reported, with patterns only matching lines |
| `profile` | optional `patterns` | configuration profiles from `profiles show` (user profiles; computer-wide profiles need root); without patterns every non-internal profile is reported, with patterns only profiles with a matching payload type |

| `browserExtension` | `patterns` | one line per extension in Chrome, Brave, Edge, Arc, Chromium, Vivaldi (every profile, newest version) and Firefox (user add-ons): `browser=<name> id=<id> name=<name> update=<update URL, addons.mozilla.org for Mozilla-signed add-ons, or none> permissions=<comma-separated>` |

An older Bluehat skips rules whose `check` it doesn't know and says how many it skipped, so new check types never break existing installs.
