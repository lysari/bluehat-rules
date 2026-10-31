import base64
import http.client
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
import zipfile
import zlib
from collections import Counter
from datetime import datetime, timedelta, timezone

API_URL = "https://mb-api.abuse.ch/api/v1/"
OSV_EXPORT_URL = "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip"
FEED_FILE = "feed.signed.json"
SOURCE = "MalwareBazaar"
SCHEMA = 1
MACOS_FILE_TYPES = ("macho", "dmg", "pkg", "app")
MACOS_TAGS = ("macOS", "macos", "osx", "AMOS", "AtomicStealer", "Poseidon", "Banshee", "Cuckoo", "Odyssey", "MacSync")
MACOS_MARKERS = ("macos", "osx", "mac", "apple", "amos", "atomicstealer")
QUERY_LIMIT = 1000
REQUEST_TIMEOUT_SECONDS = 60
MAX_RESPONSE_BYTES = 20_000_000
MAX_EXPORT_BYTES = 1_000_000_000
MAX_RECORD_BYTES = 5_000_000
MAX_HASHES = 10000
MAX_NEW_HASHES = 500
MAX_PACKAGES = 20000
MAX_PACKAGE_VERSIONS = 100
MAX_PACKAGE_NAME_BYTES = 214
MAX_VERSION_LENGTH = 256
MAX_ENVELOPE_BYTES = 4_000_000
SIGNATURE_BYTES = 64
RETENTION_DAYS = 365
VALIDITY_DAYS = 7
REFRESH_BEFORE_EXPIRY_DAYS = 2
ENTRY_FIELDS = {"sha256", "family", "firstSeen"}
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
DATE_PATTERN = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
FAMILY_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}")
PACKAGE_FIELDS = {"name", "versions", "advisory", "family"}
EVERY_VERSION = "*"
RECORD_FILE_PATTERN = re.compile(r"MAL-[0-9]{4}-[0-9]{1,12}\.json")
PACKAGE_NAME_PATTERN = re.compile(r"(@[a-z0-9~-][a-z0-9._~-]*/)?[a-z0-9~-][a-z0-9._~-]*")
VERSION_PATTERN = re.compile(r"(0|[1-9][0-9]{0,15})\.(0|[1-9][0-9]{0,15})\.(0|[1-9][0-9]{0,15})(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?")
ADVISORY_PATTERN = re.compile(r"[A-Z][A-Z0-9]{1,15}-[A-Za-z0-9._-]{1,48}")
VERSION_RANGE_TYPES = ("SEMVER", "ECOSYSTEM")
SPAM_FAMILY = "tea.xyz spam"
CAMPAIGNS = (
    ("Mini Shai-Hulud", re.compile(r"\bMini Shai-Hulud\b")),
    ("Shai-Hulud 2.0", re.compile(r"compromised by the Sha1-Hulud: The Second Coming NPM worm")),
    ("Shai-Hulud Here We Go Again", re.compile(r"Shai-Hulud: Here We Go Again")),
    ("Shai-Hulud", re.compile(r"compromised by the Shai-Hulud NPM worm")),
    ("s1ngularity", re.compile(r"s1ngularity-repository")),
    (SPAM_FAMILY, re.compile(r"part of the tea\.xyz token reward campaign")),
)


class RedirectRefuser(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


OPENER = urllib.request.build_opener(RedirectRefuser)


def log(message):
    print(message, flush=True)


def fail(message):
    print(f"::error::{message}", flush=True)
    sys.exit(1)


def format_time(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(value):
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def field(container, key, kind):
    value = container.get(key) if isinstance(container, dict) else None
    return value if isinstance(value, kind) else kind()


def query_bazaar(auth_key, form):
    request = urllib.request.Request(API_URL, data=urllib.parse.urlencode(form).encode(), headers={"Auth-Key": auth_key})
    with OPENER.open(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
        body = response.read(MAX_RESPONSE_BYTES + 1)
    if len(body) > MAX_RESPONSE_BYTES:
        raise ValueError(f"response is larger than {MAX_RESPONSE_BYTES} bytes")
    return json.loads(body)


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


def has_family(sample):
    family = sample.get("signature")
    return isinstance(family, str) and family != ""


def family_of(sample):
    family = sample.get("signature")
    return family if isinstance(family, str) and FAMILY_PATTERN.fullmatch(family) else ""


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


def collect_entries(samples):
    macos_samples = [sample for sample in samples if is_macos(sample)]
    entries = [entry_from(sample) for sample in macos_samples if has_family(sample)]
    included = {entry["sha256"] for entry in entries}
    unnamed = {entry_from(sample)["sha256"] for sample in macos_samples} - included
    log(f"{len(unnamed)} macOS samples have no MalwareBazaar family (signature) and are left out")
    excluded = {entry_from(sample)["sha256"] for sample in samples} - included
    return entries, excluded


def merge_entries(existing_entries, new_entries, excluded, now):
    merged = {}
    dropped = 0
    for entry in existing_entries + new_entries:
        problem = entry_problem(entry)
        if problem:
            sha256 = entry.get("sha256") if isinstance(entry, dict) else None
            log(f"skipping {str(sha256)[:80]!r}: {problem}")
            continue
        if entry["sha256"] in excluded:
            dropped += 1
            continue
        current = merged.get(entry["sha256"])
        if current is None or entry["firstSeen"] < current["firstSeen"]:
            merged[entry["sha256"]] = entry
    cutoff = (now - timedelta(days=RETENTION_DAYS)).date().isoformat()
    entries = sorted((entry for entry in merged.values() if entry["firstSeen"] >= cutoff), key=lambda entry: entry["sha256"])
    entries.sort(key=lambda entry: entry["firstSeen"], reverse=True)
    if dropped:
        log(f"dropped {dropped} published hashes that MalwareBazaar now lists without a family or macOS marker")
    return entries[:MAX_HASHES]


def fetch_export():
    with OPENER.open(OSV_EXPORT_URL, timeout=REQUEST_TIMEOUT_SECONDS) as response:
        body = response.read(MAX_EXPORT_BYTES + 1)
    if len(body) > MAX_EXPORT_BYTES:
        raise ValueError(f"export is larger than {MAX_EXPORT_BYTES} bytes")
    return body


def read_record(archive, info):
    if info.file_size > MAX_RECORD_BYTES:
        return None
    with archive.open(info) as handle:
        body = handle.read(MAX_RECORD_BYTES + 1)
    if len(body) > MAX_RECORD_BYTES:
        return None
    try:
        record = json.loads(body)
    except (ValueError, RecursionError):
        return None
    return record if isinstance(record, dict) else None


def is_version(version):
    return isinstance(version, str) and version.isascii() and len(version) <= MAX_VERSION_LENGTH and VERSION_PATTERN.fullmatch(version) is not None


def package_problem(entry):
    if not isinstance(entry, dict) or set(entry) != PACKAGE_FIELDS:
        return f"fields must be {sorted(PACKAGE_FIELDS)}"
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


def affected_versions(affected):
    for version_range in field(affected, "ranges", list):
        events = field(version_range, "events", list)
        is_open = all(isinstance(event, dict) and set(event) == {"introduced"} for event in events)
        if field(version_range, "type", str) in VERSION_RANGE_TYPES and is_open and {"introduced": "0"} in events:
            return EVERY_VERSION
    return sorted({version for version in field(affected, "versions", list) if is_version(version)}) or None


def family_of_record(record):
    text = field(record, "summary", str) + "\n" + field(record, "details", str)
    return next((family for family, pattern in CAMPAIGNS if pattern.search(text)), "")


def record_packages(record):
    family = family_of_record(record)
    return [
        {"name": field(field(affected, "package", dict), "name", str), "versions": affected_versions(affected), "advisory": field(record, "id", str), "family": family}
        for affected in field(record, "affected", list)
        if field(field(affected, "package", dict), "ecosystem", str) == "npm"
    ]


def priority_of(entry):
    if entry["family"] == SPAM_FAMILY:
        return 2
    return 1 if entry["versions"] == EVERY_VERSION else 0


def collect_packages(export):
    candidates = []
    problems = Counter()
    records = 0
    with zipfile.ZipFile(io.BytesIO(export)) as archive:
        for info in archive.infolist():
            if not RECORD_FILE_PATTERN.fullmatch(info.filename):
                continue
            records += 1
            record = read_record(archive, info)
            if record is None:
                problems[f"not a JSON object of at most {MAX_RECORD_BYTES} bytes"] += 1
                continue
            if field(record, "withdrawn", str):
                problems["withdrawn"] += 1
                continue
            for entry in record_packages(record):
                problem = package_problem(entry)
                if problem:
                    problems[problem] += 1
                else:
                    candidates.append((entry, field(record, "published", str)))
    candidates.sort(key=lambda candidate: candidate[0]["advisory"])
    candidates.sort(key=lambda candidate: candidate[1], reverse=True)
    candidates.sort(key=lambda candidate: priority_of(candidate[0]))
    merged = {}
    for entry, _ in candidates:
        current = merged.get(entry["name"])
        if current is None or (current["versions"] != EVERY_VERSION and entry["versions"] == EVERY_VERSION):
            merged[entry["name"]] = entry
        elif current["versions"] != EVERY_VERSION:
            current["versions"] = sorted(set(current["versions"]) | set(entry["versions"]))
    packages = [entry for entry in merged.values() if not package_problem(entry)]
    if len(packages) < len(merged):
        problems[f"more than {MAX_PACKAGE_VERSIONS} versions after merging duplicates"] = len(merged) - len(packages)
    log(f"OSV: {records} MAL records, {len(packages)} npm packages, skipped {dict(sorted(problems.items()))}")
    if len(packages) > MAX_PACKAGES:
        log(f"kept the {MAX_PACKAGES} highest-priority of {len(packages)} npm packages")
    kept = packages[:MAX_PACKAGES]
    log(f"npm packages by family: {Counter(entry['family'] or 'unknown' for entry in kept).most_common()}")
    return kept


def read_feed(path):
    if not os.path.exists(path):
        return None
    with open(path) as handle:
        envelope = json.load(handle)
    return json.loads(base64.b64decode(envelope["rules"]))


def needs_update(existing_feed, feed, now):
    if existing_feed is None:
        return True
    if {entry["sha256"] for entry in feed["hashes"]} != {entry["sha256"] for entry in existing_feed["hashes"]}:
        return True
    if feed["packages"] != existing_feed.get("packages", []):
        return True
    return parse_time(existing_feed["expires"]) - now <= timedelta(days=REFRESH_BEFORE_EXPIRY_DAYS)


def build_feed(entries, packages, now):
    issued = now.replace(microsecond=0)
    return {
        "schema": SCHEMA,
        "version": int(issued.strftime("%Y%m%d%H%M")),
        "issued": format_time(issued),
        "expires": format_time(issued + timedelta(days=VALIDITY_DAYS)),
        "source": SOURCE,
        "hashes": entries,
        "packages": packages,
    }


def payload_of(feed):
    return json.dumps(feed, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def fitted_feed(entries, packages, now):
    kept, limit = 0, len(packages)
    while kept < limit:
        middle = (kept + limit + 1) // 2
        if len(build_envelope(payload_of(build_feed(entries, packages[:middle], now)), bytes(SIGNATURE_BYTES))) < MAX_ENVELOPE_BYTES:
            kept = middle
        else:
            limit = middle - 1
    if kept < len(packages):
        log(f"left out the {len(packages) - kept} lowest-priority npm packages so the feed stays under {MAX_ENVELOPE_BYTES} bytes")
    return build_feed(entries, packages[:kept], now)


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
    new_entries, excluded = collect_entries(fetch_samples(auth_key))
    entries = merge_entries(existing_entries, new_entries, excluded, now)
    if not entries:
        fail("the merged feed has no hashes")
    existing_hashes = {entry["sha256"] for entry in existing_entries}
    added = [entry for entry in entries if entry["sha256"] not in existing_hashes]
    if len(added) > MAX_NEW_HASHES:
        families = Counter(entry["family"] or "unknown" for entry in added).most_common(20)
        log(f"new hashes by family: {families}")
        fail(f"{len(added)} new hashes is more than the {MAX_NEW_HASHES} one run may add; review them and raise MAX_NEW_HASHES if they are genuine")
    try:
        packages = collect_packages(fetch_export())
    except (OSError, ValueError, http.client.HTTPException, zipfile.BadZipFile, zlib.error, EOFError, NotImplementedError, RuntimeError) as error:
        fail(f"the OSV npm export could not be read ({type(error).__name__}: {error})")
    if not packages:
        fail("the OSV npm export gave no malicious packages")
    feed = fitted_feed(entries, packages, now)
    if not needs_update(existing_feed, feed, now):
        log(f"Feed unchanged: {len(entries)} hashes, {len(feed['packages'])} npm packages, expires {existing_feed['expires']}")
        return
    if existing_feed and feed["version"] <= existing_feed["version"]:
        fail(f"version {feed['version']} is not higher than the published {existing_feed['version']}; run again in a minute")
    payload = payload_of(feed)
    envelope = build_envelope(payload, sign(payload, signing_key))
    if len(envelope) >= MAX_ENVELOPE_BYTES:
        fail(f"feed envelope is {len(envelope)} bytes, the limit is {MAX_ENVELOPE_BYTES}")
    with open(FEED_FILE, "wb") as handle:
        handle.write(envelope)
    every_version = sum(1 for entry in feed["packages"] if entry["versions"] == EVERY_VERSION)
    log(f"Wrote {FEED_FILE} v{feed['version']}: {len(entries)} hashes ({len(added)} new), {len(feed['packages'])} npm packages ({every_version} for every version), expires {feed['expires']}")


if __name__ == "__main__":
    main()
