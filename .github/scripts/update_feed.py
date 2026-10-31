import base64
import http.client
import json
import os
import re
import subprocess
import sys
import tempfile
import unicodedata
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

API_URL = "https://mb-api.abuse.ch/api/v1/"
FEED_FILE = "feed.signed.json"
SOURCE = "MalwareBazaar"
SCHEMA = 1
MACOS_FILE_TYPES = ("macho", "dmg", "pkg", "app")
MACOS_TAGS = ("macOS", "macos", "osx", "AMOS", "AtomicStealer", "Poseidon", "Banshee", "Cuckoo", "Odyssey", "MacSync")
PLATFORM_MARKERS = ("macos", "osx", "mac", "apple")
MACOS_MARKERS = PLATFORM_MARKERS + ("amos", "atomicstealer")
QUERY_LIMIT = 1000
REQUEST_TIMEOUT_SECONDS = 60
MAX_HASHES = 10000
MAX_ENVELOPE_BYTES = 4_000_000
MAX_FAMILY_LENGTH = 64
RETENTION_DAYS = 365
VALIDITY_DAYS = 7
REFRESH_BEFORE_EXPIRY_DAYS = 2
ENTRY_FIELDS = {"sha256", "family", "firstSeen"}
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
DATE_PATTERN = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")


def log(message):
    print(message, flush=True)


def fail(message):
    print(f"::error::{message}", flush=True)
    sys.exit(1)


def format_time(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(value):
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def query_bazaar(auth_key, form):
    request = urllib.request.Request(API_URL, data=urllib.parse.urlencode(form).encode(), headers={"Auth-Key": auth_key})
    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
        return json.load(response)


def fetch_samples(auth_key):
    queries = [{"query": "get_file_type", "file_type": file_type, "limit": QUERY_LIMIT} for file_type in MACOS_FILE_TYPES]
    queries += [{"query": "get_taginfo", "tag": tag, "limit": QUERY_LIMIT} for tag in MACOS_TAGS]
    samples = []
    succeeded = 0
    for form in queries:
        label = f"{form['query']} {form.get('file_type', form.get('tag'))}"
        try:
            response = query_bazaar(auth_key, form)
        except (OSError, ValueError, http.client.HTTPException) as error:
            log(f"{label}: request failed ({type(error).__name__}: {error})")
            continue
        status = response.get("query_status") if isinstance(response, dict) else None
        data = response.get("data") if status == "ok" else None
        if not isinstance(data, list):
            log(f"{label}: {status!r}, 0 samples")
            continue
        succeeded += 1
        log(f"{label}: ok, {len(data)} samples")
        samples += [sample for sample in data if isinstance(sample, dict)]
    if succeeded == 0:
        fail("every MalwareBazaar query failed")
    return samples


def tags_of(sample):
    tags = sample.get("tags")
    return [tag for tag in tags if isinstance(tag, str)] if isinstance(tags, list) else []


def is_macos(sample):
    file_type = sample.get("file_type")
    if isinstance(file_type, str) and file_type.lower() in MACOS_FILE_TYPES:
        return True
    return any(tag.lower() in MACOS_MARKERS for tag in tags_of(sample))


def family_of(sample):
    signature = sample.get("signature")
    if isinstance(signature, str) and signature:
        return signature
    return next((tag for tag in tags_of(sample) if tag.lower() not in PLATFORM_MARKERS + MACOS_FILE_TYPES), "")


def entry_from(sample):
    sha256 = sample.get("sha256_hash")
    try:
        first_seen = datetime.strptime(sample.get("first_seen"), "%Y-%m-%d %H:%M:%S").date().isoformat()
    except (TypeError, ValueError):
        first_seen = None
    return {"sha256": sha256.lower() if isinstance(sha256, str) else sha256, "family": family_of(sample), "firstSeen": first_seen}


def entry_problem(entry):
    if not isinstance(entry, dict) or set(entry) != ENTRY_FIELDS:
        return f"fields must be {sorted(ENTRY_FIELDS)}"
    if not isinstance(entry["sha256"], str) or not SHA256_PATTERN.fullmatch(entry["sha256"]):
        return "sha256 is not 64 lowercase hex characters"
    family = entry["family"]
    if not isinstance(family, str) or len(family) > MAX_FAMILY_LENGTH:
        return f"family is longer than {MAX_FAMILY_LENGTH} characters"
    if any(unicodedata.category(character) in ("Cc", "Cf") for character in family):
        return "family contains control characters"
    first_seen = entry["firstSeen"]
    if not isinstance(first_seen, str) or not DATE_PATTERN.fullmatch(first_seen):
        return "firstSeen is not YYYY-MM-DD"
    try:
        datetime.strptime(first_seen, "%Y-%m-%d")
    except ValueError:
        return "firstSeen is not a real date"
    return None


def collect_entries(samples):
    return [entry_from(sample) for sample in samples if is_macos(sample)]


def merge_entries(existing_entries, new_entries, now):
    merged = {}
    for entry in existing_entries + new_entries:
        problem = entry_problem(entry)
        if problem:
            sha256 = entry.get("sha256") if isinstance(entry, dict) else None
            log(f"skipping {str(sha256)[:80]!r}: {problem}")
            continue
        current = merged.get(entry["sha256"])
        if current is None or entry["firstSeen"] < current["firstSeen"]:
            merged[entry["sha256"]] = entry
    cutoff = (now - timedelta(days=RETENTION_DAYS)).date().isoformat()
    entries = sorted((entry for entry in merged.values() if entry["firstSeen"] >= cutoff), key=lambda entry: entry["sha256"])
    entries.sort(key=lambda entry: entry["firstSeen"], reverse=True)
    return entries[:MAX_HASHES]


def read_feed(path):
    if not os.path.exists(path):
        return None
    with open(path) as handle:
        envelope = json.load(handle)
    return json.loads(base64.b64decode(envelope["rules"]))


def needs_update(existing_feed, entries, now):
    if existing_feed is None:
        return True
    if {entry["sha256"] for entry in entries} != {entry["sha256"] for entry in existing_feed["hashes"]}:
        return True
    return parse_time(existing_feed["expires"]) - now <= timedelta(days=REFRESH_BEFORE_EXPIRY_DAYS)


def build_feed(entries, now):
    issued = now.replace(microsecond=0)
    return {
        "schema": SCHEMA,
        "version": int(issued.strftime("%Y%m%d%H%M")),
        "issued": format_time(issued),
        "expires": format_time(issued + timedelta(days=VALIDITY_DAYS)),
        "source": SOURCE,
        "hashes": entries,
    }


def sign(payload, private_key_pem):
    with tempfile.TemporaryDirectory() as directory:
        key_path = os.path.join(directory, "key.pem")
        payload_path = os.path.join(directory, "payload")
        signature_path = os.path.join(directory, "signature")
        with os.fdopen(os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as handle:
            handle.write(private_key_pem)
        with open(payload_path, "wb") as handle:
            handle.write(payload)
        try:
            result = subprocess.run(
                ["openssl", "pkeyutl", "-sign", "-inkey", key_path, "-rawin", "-in", payload_path, "-out", signature_path],
                capture_output=True,
            )
        finally:
            os.remove(key_path)
        if result.returncode != 0:
            fail("openssl could not sign the feed; check that FEED_SIGNING_KEY is a PKCS#8 Ed25519 private key")
        with open(signature_path, "rb") as handle:
            return handle.read()


def build_envelope(payload, signature):
    envelope = {"rules": base64.b64encode(payload).decode(), "signature": base64.b64encode(signature).decode()}
    return json.dumps(envelope, indent=2, sort_keys=True, separators=(",", " : ")).encode()


def main():
    auth_key = os.environ.get("ABUSE_CH_AUTH_KEY", "")
    signing_key = os.environ.get("FEED_SIGNING_KEY", "")
    if not auth_key or not signing_key:
        fail("ABUSE_CH_AUTH_KEY and FEED_SIGNING_KEY must be set")
    now = datetime.now(timezone.utc)
    existing_feed = read_feed(FEED_FILE)
    existing_entries = existing_feed["hashes"] if existing_feed else []
    entries = merge_entries(existing_entries, collect_entries(fetch_samples(auth_key)), now)
    if not entries:
        fail("the merged feed has no hashes")
    if not needs_update(existing_feed, entries, now):
        log(f"Feed unchanged: {len(entries)} hashes, expires {existing_feed['expires']}")
        return
    feed = build_feed(entries, now)
    if existing_feed and feed["version"] <= existing_feed["version"]:
        fail(f"version {feed['version']} is not higher than the published {existing_feed['version']}; run again in a minute")
    payload = json.dumps(feed, sort_keys=True, separators=(",", ":")).encode()
    envelope = build_envelope(payload, sign(payload, signing_key))
    if len(envelope) >= MAX_ENVELOPE_BYTES:
        fail(f"feed envelope is {len(envelope)} bytes, the limit is {MAX_ENVELOPE_BYTES}")
    with open(FEED_FILE, "wb") as handle:
        handle.write(envelope)
    added = len({entry["sha256"] for entry in entries} - {entry["sha256"] for entry in existing_entries})
    log(f"Wrote {FEED_FILE} v{feed['version']}: {len(entries)} hashes ({added} new), expires {feed['expires']}")


if __name__ == "__main__":
    main()
