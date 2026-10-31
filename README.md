# bluehat-rules

Detection rules for the Bluehat macOS menu bar scanner.

The app downloads only `rules.signed.json` (hand-written rules) and `feed.signed.json` (malware fingerprints) from this repository and rejects each unless it is signed by a key the app trusts for that file. Both are data only: each rule picks one of the check types the app has built in, and the feed holds only file hashes, so nothing in this repository can make the app run code.

## Update the rules

1. Edit `rules.json`.
2. Raise `version` (format `YYYYMMDDNN`). The app refuses a version lower than the last one it verified.
3. Sign: `devbox run sign-rules` from the Bluehat project. The signer adds a signed `issued` time to the published copy; don't put it in `rules.json` yourself.
4. Commit and push both `rules.json` and `rules.signed.json`.

Hand-written rules expire 1 year after signing: the signer stamps `issued` and `expires` (1 year later) into the signed copy, and the app warns 30 days before expiry and refuses expired rules, so sign and push again (raise `version`) before then, even with no rule changes. Someone who blocks updates or keeps serving an old signed file can't freeze your rules for longer than that, and the app refuses versions below its built-in minimum, so old signed files without an expiry can't be replayed to a fresh install. Fingerprints update daily on their own (see below).

## Malware fingerprint feed

`feed.signed.json` lists SHA-256 hashes of recent macOS malware samples from [MalwareBazaar](https://bazaar.abuse.ch/) (abuse.ch), so the app's file hash check knows current attacks without a hand-written rule for each sample.

- `.github/workflows/update-feed.yml` runs `.github/scripts/update_feed.py` daily at 03:17 UTC (and on demand from the Actions tab). It queries MalwareBazaar for macOS file types (`macho`, `dmg`, `pkg`, `app`) and macOS tags (`macOS`, `osx`, `AMOS`, `AtomicStealer` and other stealer families), keeps samples with a macOS file type or tag, merges them with the current feed, drops hashes first seen more than 365 days ago, keeps the 10000 newest, signs the result and commits it as `github-actions[bot]`. The log lists each query's status and sample count.
- It only commits when the set of hashes changed or the published feed expires within 2 days. The feed expires 7 days after signing, so it stays valid while the job runs and goes stale within a week if the job stops.
- It needs two repository secrets: `ABUSE_CH_AUTH_KEY` (MalwareBazaar API key, from [auth.abuse.ch](https://auth.abuse.ch/)) and `FEED_SIGNING_KEY` (the CI feed key, a PKCS#8 PEM Ed25519 private key).
- The CI feed key can only sign the feed. The app and `verify.yml` accept it for `feed.signed.json` (`FEED_KEYS`) and never for `rules.signed.json` (`TRUSTED_KEYS`), so a leaked CI key can add hashes but can't change the rules. The hand-written rules are still signed only by the owner's keys.

The envelope is `{"rules": "<base64 payload>", "signature": "<base64 Ed25519 signature of the payload bytes>"}` (the field is called `rules` in both files). The payload is JSON:

| Field | Values |
|---|---|
| `schema` | `1` |
| `version` | UTC time of the run as `YYYYMMDDHHMM` |
| `issued`, `expires` | ISO 8601 UTC times, `expires` is 7 days after `issued` |
| `source` | `MalwareBazaar` |
| `hashes` | up to 10000 entries, newest `firstSeen` first: `sha256` (64 lowercase hex), `family` (0-64 characters, no control characters, empty when unknown), `firstSeen` (`YYYY-MM-DD`) |

The whole file stays under 4,000,000 bytes.

## Checks on every push

`.github/workflows/verify.yml` runs `.github/scripts/verify_rules.py` (Python standard library and OpenSSL only). It fails when `rules.signed.json` isn't signed by a trusted key, doesn't match `rules.json`, has no `issued`/`expires`, has expired, has duplicate ids, or changed without a higher `version`, and when `feed.signed.json` isn't signed by a key in `FEED_KEYS`, has expired, is too large, or has an invalid or duplicate entry. Its `TRUSTED_KEYS` must list the same public keys as the app's `RuleFeed.trustedKeys`, and `FEED_KEYS` the keys the app accepts for the feed: the CI feed key plus the owner's keys. Pushes by the feed job don't trigger this workflow (GitHub doesn't start workflows from `GITHUB_TOKEN` pushes); the next owner push checks the feed too. It is a consistency check, not the security boundary: the app verifies everything itself.

## Signing keys

- Primary key: in the owner's login Keychain (service `bluehat-rules-signing`), created with `bluehat-sign keygen`.
- Current trusted keys: primary `07:50:0B:8A:44:2C:EE:F7` (Keychain), backup `45:F7:3C:B2:FC:D3:CE:3E` (offline).
- CI feed key: public key `srVF3Dxj32r6pMW0M+0MMsUdr75RyoD94CafL7iFnoE=`, private key only in the `FEED_SIGNING_KEY` repository secret. Feed only; never add it to `TRUSTED_KEYS` or `RuleFeed.trustedKeys`. If it leaks, remove it from the app's feed keys and `FEED_KEYS`, create a new one and replace the secret.
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
