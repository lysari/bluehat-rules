import base64
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

ED25519_PUBLIC_KEY_PREFIX = bytes.fromhex("302a300506032b6570032100")
STAMPED_FIELDS = ("issued", "expires")
FEED_FILE = "feed.signed.json"
FEED_SCHEMA = 1
MAX_FEED_HASHES = 10000
MAX_FEED_BYTES = 4_000_000
FEED_ENTRY_FIELDS = {"sha256", "family", "firstSeen"}
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
DATE_PATTERN = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
FAMILY_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}")


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


def verified_envelope(path, keys, key_list_name):
    if not keys:
        fail(f"{key_list_name} is empty")
    envelope = json.load(open(path))
    payload = base64.b64decode(envelope["rules"])
    signature = base64.b64decode(envelope["signature"])
    with tempfile.TemporaryDirectory() as directory:
        if not any(verified_by(key, payload, signature, directory) for key in keys):
            fail(f"{path} is not signed by a key in {key_list_name}")
    return envelope, json.loads(payload)


def previous_signed_version():
    result = subprocess.run(["git", "show", "HEAD~1:rules.signed.json"], capture_output=True)
    if result.returncode != 0:
        return None, None
    envelope = json.loads(result.stdout)
    return envelope, json.loads(base64.b64decode(envelope["rules"]))["version"]


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def feed_entry_problem(entry):
    if not isinstance(entry, dict) or set(entry) != FEED_ENTRY_FIELDS:
        return f"fields must be {sorted(FEED_ENTRY_FIELDS)}"
    if not isinstance(entry["sha256"], str) or not SHA256_PATTERN.fullmatch(entry["sha256"]):
        return "sha256 is not 64 lowercase hex characters"
    family = entry["family"]
    if not isinstance(family, str) or (family and not FAMILY_PATTERN.fullmatch(family)):
        return "family is not empty or 1-64 letters, digits, spaces, '.', '_' or '-' starting with a letter or digit"
    first_seen = entry["firstSeen"]
    if not isinstance(first_seen, str) or not DATE_PATTERN.fullmatch(first_seen):
        return "firstSeen is not YYYY-MM-DD"
    try:
        datetime.strptime(first_seen, "%Y-%m-%d")
    except ValueError:
        return "firstSeen is not a real date"
    return None


def verify_feed():
    if os.path.getsize(FEED_FILE) >= MAX_FEED_BYTES:
        fail(f"{FEED_FILE} is larger than {MAX_FEED_BYTES} bytes")
    _, feed = verified_envelope(FEED_FILE, os.environ.get("FEED_KEYS", "").split(), "FEED_KEYS")
    if feed.get("schema") != FEED_SCHEMA:
        fail(f"feed schema {feed.get('schema')} is not {FEED_SCHEMA}")
    if not isinstance(feed.get("version"), int):
        fail("feed has no integer version")
    for field in STAMPED_FIELDS:
        if not isinstance(feed.get(field), str):
            fail(f"feed has no {field} time")
    if parse_time(feed["expires"]) <= datetime.now(timezone.utc):
        fail(f"feed expired at {feed['expires']}")
    hashes = feed.get("hashes")
    if not isinstance(hashes, list) or not 0 < len(hashes) <= MAX_FEED_HASHES:
        fail(f"feed must list 1-{MAX_FEED_HASHES} hashes")
    for index, entry in enumerate(hashes):
        problem = feed_entry_problem(entry)
        if problem:
            fail(f"feed entry {index}: {problem}")
    if len({entry["sha256"] for entry in hashes}) != len(hashes):
        fail("feed hashes are not unique")
    print(f"Verified feed v{feed['version']}: {len(hashes)} hashes, signed {feed['issued']}, expires {feed['expires']}")


def main():
    envelope, signed = verified_envelope("rules.signed.json", os.environ.get("TRUSTED_KEYS", "").split(), "TRUSTED_KEYS")
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

    if os.path.exists(FEED_FILE):
        verify_feed()


main()
