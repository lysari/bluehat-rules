import base64
import ipaddress
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
MAX_FEED_PACKAGES = 20000
MAX_FEED_HOSTS = 5000
MAX_PACKAGE_VERSIONS = 100
MAX_PACKAGE_NAME_BYTES = 214
MAX_VERSION_LENGTH = 256
MAX_FEED_BYTES = 4_000_000
FEED_ENTRY_FIELDS = {"sha256", "family", "firstSeen"}
FEED_PACKAGE_FIELDS = {"name", "versions", "advisory", "family"}
FEED_HOST_FIELDS = {"host", "family", "firstSeen"}
EVERY_VERSION = "*"
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
DATE_PATTERN = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
FAMILY_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}")
PACKAGE_NAME_PATTERN = re.compile(r"(@[a-z0-9~-][a-z0-9._~-]*/)?[a-z0-9~-][a-z0-9._~-]*")
VERSION_PATTERN = re.compile(r"(0|[1-9][0-9]{0,15})\.(0|[1-9][0-9]{0,15})\.(0|[1-9][0-9]{0,15})(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?")
ADVISORY_PATTERN = re.compile(r"[A-Z][A-Z0-9]{1,15}-[A-Za-z0-9._-]{1,48}")
HOST_PATTERN = re.compile(r"(\[[0-9a-f:.]{2,45}\]|[0-9.]{7,15}):[1-9][0-9]{0,4}")


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


def is_version(version):
    return isinstance(version, str) and version.isascii() and len(version) <= MAX_VERSION_LENGTH and VERSION_PATTERN.fullmatch(version) is not None


def feed_package_problem(entry):
    if not isinstance(entry, dict) or set(entry) != FEED_PACKAGE_FIELDS:
        return f"fields must be {sorted(FEED_PACKAGE_FIELDS)}"
    name = entry["name"]
    if not isinstance(name, str) or not name.isascii() or len(name) > MAX_PACKAGE_NAME_BYTES or not PACKAGE_NAME_PATTERN.fullmatch(name):
        return f"name is not a lowercase npm package name of at most {MAX_PACKAGE_NAME_BYTES} bytes"
    versions = entry["versions"]
    if versions != EVERY_VERSION and (not isinstance(versions, list) or not 0 < len(versions) <= MAX_PACKAGE_VERSIONS):
        return f'versions is not "*" or a list of 1-{MAX_PACKAGE_VERSIONS} versions'
    if versions != EVERY_VERSION and not all(is_version(version) for version in versions):
        return "versions are not all semver versions such as 1.2.3"
    if not isinstance(entry["advisory"], str) or not ADVISORY_PATTERN.fullmatch(entry["advisory"]):
        return "advisory is not an id such as MAL-2025-46969"
    family = entry["family"]
    if not isinstance(family, str) or (family and not FAMILY_PATTERN.fullmatch(family)):
        return "family is not empty or 1-64 letters, digits, spaces, '.', '_' or '-' starting with a letter or digit"
    return None


def feed_host_problem(entry):
    if not isinstance(entry, dict) or set(entry) != FEED_HOST_FIELDS:
        return f"fields must be {sorted(FEED_HOST_FIELDS)}"
    host = entry["host"]
    if not isinstance(host, str) or not HOST_PATTERN.fullmatch(host):
        return "host is not an IPv4 address:port or [IPv6 address]:port"
    address, _, port = host.rpartition(":")
    try:
        parsed = ipaddress.ip_address(address.removeprefix("[").removesuffix("]"))
    except ValueError:
        return "host is not an IPv4 address:port or [IPv6 address]:port"
    if (parsed.version == 6) != address.startswith("[") or not parsed.is_global or int(port) > 65535:
        return "host is not a public address, or its port is not 1-65535"
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
    packages = feed.get("packages", [])
    if not isinstance(packages, list) or len(packages) > MAX_FEED_PACKAGES:
        fail(f"feed must list at most {MAX_FEED_PACKAGES} npm packages")
    for index, entry in enumerate(packages):
        problem = feed_package_problem(entry)
        if problem:
            fail(f"feed npm package {index}: {problem}")
    hosts = feed.get("hosts", [])
    if not isinstance(hosts, list) or len(hosts) > MAX_FEED_HOSTS:
        fail(f"feed must list at most {MAX_FEED_HOSTS} C2 addresses")
    for index, entry in enumerate(hosts):
        problem = feed_host_problem(entry)
        if problem:
            fail(f"feed C2 address {index}: {problem}")
    if len({entry["host"] for entry in hosts}) != len(hosts):
        fail("feed C2 addresses are not unique")
    print(f"Verified feed v{feed['version']}: {len(hashes)} hashes, {len(packages)} npm packages, {len(hosts)} C2 addresses, signed {feed['issued']}, expires {feed['expires']}")


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
