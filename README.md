# bluehat-rules

Detection rules for the Bluehat macOS menu bar scanner.

The app downloads only `rules.signed.json` from this repository and rejects it unless it is signed by the owner's Ed25519 key, whose public half is built into the app. Rules are data only: each rule picks one of the check types the app has built in, so nothing in this repository can make the app run code.

## Update the rules

1. Edit `rules.json`.
2. Raise `version` (format `YYYYMMDDNN`). The app refuses a version lower than the last one it verified.
3. Sign: `devbox run sign-rules` from the Bluehat project. The signer adds a signed `issued` time to the published copy; don't put it in `rules.json` yourself.
4. Commit and push both `rules.json` and `rules.signed.json`.

Sign and push at least every 14 days, even with no rule changes (raise `version`). The app warns when the rules it trusts were signed more than 14 days ago, so someone who blocks updates or keeps serving an old signed file can't silently freeze your rules.

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

An older Bluehat skips rules whose `check` it doesn't know and says how many it skipped, so new check types never break existing installs.
