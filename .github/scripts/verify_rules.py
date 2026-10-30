import base64
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

ED25519_PUBLIC_KEY_PREFIX = bytes.fromhex("302a300506032b6570032100")
STAMPED_FIELDS = ("issued", "expires")


def fail(message):
    print(f"::error::{message}")
    sys.exit(1)


def public_key_pem(raw_base64):
    der = ED25519_PUBLIC_KEY_PREFIX + base64.b64decode(raw_base64)
    return "-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(der).decode() + "\n-----END PUBLIC KEY-----\n"


def verified_by(key, payload, signature, directory):
    paths = {name: os.path.join(directory, name) for name in ("key.pem", "payload", "signature")}
    with open(paths["key.pem"], "w") as handle:
        handle.write(public_key_pem(key))
    with open(paths["payload"], "wb") as handle:
        handle.write(payload)
    with open(paths["signature"], "wb") as handle:
        handle.write(signature)
    result = subprocess.run(
        ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", paths["key.pem"], "-rawin", "-in", paths["payload"], "-sigfile", paths["signature"]],
        capture_output=True,
    )
    return result.returncode == 0


def previous_signed_version():
    result = subprocess.run(["git", "show", "HEAD~1:rules.signed.json"], capture_output=True)
    if result.returncode != 0:
        return None, None
    envelope = json.loads(result.stdout)
    return envelope, json.loads(base64.b64decode(envelope["rules"]))["version"]


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def main():
    trusted_keys = os.environ.get("TRUSTED_KEYS", "").split()
    if not trusted_keys:
        fail("TRUSTED_KEYS is empty")
    envelope = json.load(open("rules.signed.json"))
    payload = base64.b64decode(envelope["rules"])
    signature = base64.b64decode(envelope["signature"])
    with tempfile.TemporaryDirectory() as directory:
        if not any(verified_by(key, payload, signature, directory) for key in trusted_keys):
            fail("rules.signed.json is not signed by a trusted key")

    signed = json.loads(payload)
    source = json.load(open("rules.json"))
    if {key: value for key, value in signed.items() if key not in STAMPED_FIELDS} != source:
        fail("rules.signed.json does not match rules.json; run devbox run sign-rules and commit both files")

    for field in STAMPED_FIELDS:
        if field not in signed:
            fail(f"signed rules have no {field} time")
    if parse_time(signed["expires"]) <= datetime.now(timezone.utc):
        fail(f"signed rules expired at {signed['expires']}")

    ids = [rule["id"] for rule in signed["rules"]]
    if len(ids) != len(set(ids)):
        fail("rule ids are not unique")

    previous_envelope, previous_version = previous_signed_version()
    if previous_envelope is not None and previous_envelope != envelope and signed["version"] <= previous_version:
        fail(f"version {signed['version']} must be higher than the previous {previous_version}")

    print(f"Verified v{signed['version']}: {len(ids)} rules, signed {signed['issued']}, expires {signed['expires']}")


main()
