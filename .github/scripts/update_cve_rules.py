import http.client
import json
import math
import re
import sys
import unicodedata
import urllib.error
import urllib.parse
import urllib.request

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
RULES_FILE = "rules.json"
CHECK = "softwareVersion"
ID_PREFIX = "cve."
PRODUCTS = {
    "node": {"name": "Node.js", "repo": "https://github.com/nodejs/node", "cpes": ("nodejs:node.js",)},
    "php": {"name": "PHP", "repo": "https://github.com/php/php-src", "cpes": ("php:php",)},
    "python": {"name": "Python", "repo": "https://github.com/python/cpython", "cpes": ("python:python",)},
    "openssl": {"name": "OpenSSL", "repo": "https://github.com/openssl/openssl", "cpes": ("openssl:openssl",)},
    "git": {"name": "Git", "repo": "https://github.com/git/git", "cpes": ("git-scm:git", "git:git")},
    "ruby": {"name": "Ruby", "repo": "https://github.com/ruby/ruby", "cpes": ("ruby-lang:ruby",)},
}
LETTER_RELEASE_PRODUCTS = ("openssl",)
CPE_SOURCES = ("CPE_RANGE", "CPE_STRING")
SEVERITIES = ("info", "low", "medium", "high", "critical")
MIN_SEVERITY = "high"
MAX_GENERATED_RULES = 400
MAX_RULES = 500
MAX_RANGES = 200
MAX_TITLE_LENGTH = 120
MAX_EXPLANATION_LENGTH = 600
MAX_REFERENCES = 5
MAX_REFERENCE_LENGTH = 300
MAX_ENVELOPE_BYTES = 2_000_000
ENVELOPE_OVERHEAD_BYTES = 200
STAMPED_FIELDS = {"issued": "2000-01-01T00:00:00Z", "expires": "2000-01-01T00:00:00Z"}
REQUEST_TIMEOUT_SECONDS = 60
MAX_RESPONSE_BYTES = 50_000_000
MAX_PAGES = 20
RCE_CWES = {"CWE-77", "CWE-78", "CWE-94", "CWE-95"}
RCE_TEXT = re.compile(r"remote code execution|arbitrary code|code execution|execute (?:arbitrary )?(?:code|commands)|command injection|code injection|inject(?:ing)? (?:arbitrary )?code", re.IGNORECASE)
CVE_PATTERN = re.compile(r"CVE-([0-9]{4})-([0-9]{4,19})")
BITNAMI_PATTERN = re.compile(r"BIT-[a-z0-9-]{1,64}-[0-9]{4}-[0-9]{1,19}")
RULE_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9.-]{0,63}")
ADVISORY_PATTERN = re.compile(r"[A-Z][A-Z0-9]{1,15}-[A-Za-z0-9._-]{1,48}")
RELEASE_PATTERN = re.compile(r"v?([0-9]{1,9}(?:\.[0-9]{1,9}){0,5})([a-z]{1,2})?")
PRERELEASE_PATTERN = re.compile(r"v?([0-9]{1,9}(?:\.[0-9]{1,9}){0,5})[-.]?(?:alpha|beta|preview|pre|rc|dev|a|b|c)[.-]?[0-9]{0,9}")
REFERENCE_PATTERN = re.compile(r"https://[A-Za-z0-9.-]{1,253}(?::[0-9]{1,5})?(?:/(?:[A-Za-z0-9._~:/?#@!$&'()*+,;=-]|%[0-9A-Fa-f]{2})*)?")
CVSS3_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
CVSS3_PRIVILEGES = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}


class RedirectRefuser(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


OPENER = urllib.request.build_opener(RedirectRefuser)


def log(message):
    print(message, flush=True)


def fail(message):
    print(f"error: {message}", flush=True)
    sys.exit(1)


def field(container, key, kind):
    value = container.get(key) if isinstance(container, dict) else None
    return value if isinstance(value, kind) else kind()


def fetch_json(url, body=None):
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with OPENER.open(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
        payload = response.read(MAX_RESPONSE_BYTES + 1)
    if len(payload) > MAX_RESPONSE_BYTES:
        raise ValueError(f"response is larger than {MAX_RESPONSE_BYTES} bytes")
    result = json.loads(payload)
    if not isinstance(result, dict):
        raise ValueError("response is not a JSON object")
    return result


def fetch_records(repo):
    records = []
    page_token = None
    for _ in range(MAX_PAGES):
        query = {"package": {"name": repo, "ecosystem": "GIT"}}
        if page_token:
            query["page_token"] = page_token
        response = fetch_json(OSV_QUERY_URL, query)
        records += [record for record in field(response, "vulns", list) if isinstance(record, dict)]
        page_token = field(response, "next_page_token", str)
        if not page_token:
            return records
    raise ValueError(f"more than {MAX_PAGES} pages of results")


def version_key(version):
    match = RELEASE_PATTERN.fullmatch(version)
    numbers = [int(part) for part in match.group(1).split(".")]
    while numbers and numbers[-1] == 0:
        numbers.pop()
    return tuple(numbers), match.group(2) or ""


def stable_version(text, product):
    if not isinstance(text, str):
        return None
    if text == "0":
        return "0", False
    release = RELEASE_PATTERN.fullmatch(text)
    if release and (release.group(2) is None or product in LETTER_RELEASE_PRODUCTS):
        return release.group(1) + (release.group(2) or ""), False
    prerelease = PRERELEASE_PATTERN.fullmatch(text)
    return (prerelease.group(1), True) if prerelease else None


def range_from(introduced, end_kind, end, product):
    start = stable_version(introduced, product)
    stop = stable_version(end, product)
    if start is None or stop is None:
        return None
    if end_kind == "last_affected" and not stop[1]:
        if version_key(start[0]) > version_key(stop[0]):
            return None
        return {"introduced": start[0], "lastAffected": stop[0]}
    if version_key(start[0]) >= version_key(stop[0]):
        return None
    return {"introduced": start[0], "fixed": stop[0]}


def ranges_from_events(events, product):
    ranges = []
    introduced = None
    for event in events:
        if not isinstance(event, dict) or len(event) != 1:
            return []
        kind, value = next(iter(event.items()))
        if kind == "introduced":
            introduced = value
        elif kind in ("fixed", "last_affected") and introduced is not None:
            converted = range_from(introduced, kind, value, product)
            if converted:
                ranges.append(converted)
            introduced = None
    return ranges


def cpe_product(cpe):
    parts = cpe.split(":")
    return ":".join(parts[3:5]) if len(parts) > 5 and parts[:3] == ["cpe", "2.3", "a"] else None


def extracted_ranges(record, product):
    settings = PRODUCTS[product]
    ranges = []
    for affected in field(record, "affected", list):
        for git_range in field(affected, "ranges", list):
            if field(git_range, "type", str) != "GIT" or field(git_range, "repo", str) != settings["repo"]:
                continue
            range_details = field(git_range, "database_specific", dict)
            ranges += ranges_from_events(field(range_details, "versions", list), product)
            for extracted in field(range_details, "extracted_events", list):
                source = field(extracted, "source", str)
                if source == "AFFECTED_FIELD" or (source in CPE_SOURCES and cpe_product(field(extracted, "cpe", str)) in settings["cpes"]):
                    ranges += ranges_from_events(field(extracted, "range", list), product)
    for unresolved in field(field(record, "database_specific", dict), "unresolved_ranges", list):
        if field(unresolved, "vendor_product", str) not in settings["cpes"]:
            continue
        for extracted in field(unresolved, "extracted_events", list):
            if field(extracted, "source", str) in CPE_SOURCES:
                ranges += ranges_from_events(field(extracted, "range", list), product)
    return merged_ranges(ranges)


def merged_ranges(ranges):
    merged = []
    for current in sorted(ranges, key=lambda item: (version_key(item["introduced"]), item["introduced"], item.get("fixed", ""), item.get("lastAffected", ""))):
        if merged:
            previous = merged[-1]
            previous_end = previous.get("fixed") or previous["lastAffected"]
            if version_key(current["introduced"]) <= version_key(previous_end):
                current_end = current.get("fixed") or current["lastAffected"]
                if version_key(current_end) > version_key(previous_end) or (version_key(current_end) == version_key(previous_end) and "lastAffected" in current):
                    merged[-1] = {"introduced": previous["introduced"], **{key: value for key, value in current.items() if key != "introduced"}}
                continue
        merged.append(current)
    return merged


def round_up(value):
    scaled = round(value * 100000)
    return scaled / 100000.0 if scaled % 10000 == 0 else (math.floor(scaled / 10000) + 1) / 10.0


def cvss3_score(vector):
    parts = vector.split("/")
    if parts[0] not in ("CVSS:3.0", "CVSS:3.1"):
        return None
    metrics = dict(part.split(":", 1) for part in parts[1:] if ":" in part)
    try:
        scope = metrics["S"]
        weights = {name: CVSS3_WEIGHTS[name][metrics[name]] for name in CVSS3_WEIGHTS}
        privileges = CVSS3_PRIVILEGES[scope][metrics["PR"]]
    except KeyError:
        return None
    base_impact = 1 - (1 - weights["C"]) * (1 - weights["I"]) * (1 - weights["A"])
    impact = 6.42 * base_impact if scope == "U" else 7.52 * (base_impact - 0.029) - 3.25 * (base_impact - 0.02) ** 15
    exploitability = 8.22 * weights["AV"] * weights["AC"] * privileges * weights["UI"]
    if impact <= 0:
        return 0.0
    total = impact + exploitability if scope == "U" else 1.08 * (impact + exploitability)
    return round_up(min(total, 10))


def severity_of_score(score):
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low" if score > 0 else "info"


def bitnami_severity(record):
    for alias in sorted(alias for alias in field(record, "aliases", list) if isinstance(alias, str) and BITNAMI_PATTERN.fullmatch(alias)):
        try:
            bitnami = fetch_json(OSV_VULN_URL + urllib.parse.quote(alias, safe=""))
        except urllib.error.HTTPError as error:
            if error.code == 404:
                continue
            fail(f"{alias}: OSV request failed (HTTP {error.code})")
        except (OSError, ValueError, http.client.HTTPException) as error:
            fail(f"{alias}: OSV request failed ({type(error).__name__}: {error})")
        severity = field(field(bitnami, "database_specific", dict), "severity", str).lower()
        if severity in SEVERITIES:
            return severity
    return None


def severity_of(record):
    scores = [cvss3_score(field(entry, "score", str)) for entry in field(record, "severity", list) if field(entry, "type", str) == "CVSS_V3"]
    scores = [score for score in scores if score is not None]
    return severity_of_score(max(scores)) if scores else bitnami_severity(record)


def clean_text(text):
    visible = "".join(" " if unicodedata.category(character).startswith(("C", "Z")) else character for character in text)
    return " ".join(visible.split())


def shortened(text, limit):
    if len(text) <= limit:
        return text
    cut = text[: limit - 1]
    return (cut.rsplit(" ", 1)[0] if " " in cut else cut).rstrip(" ,;:.") + "…"


def title_of(record, name, advisory):
    details = clean_text(field(record, "details", str))
    headline = clean_text(field(record, "summary", str)) or re.split(r"(?<=[.!?]) ", details, maxsplit=1)[0]
    frame = f"{name}:  ({advisory})"
    if not headline:
        return f"{name} vulnerability {advisory}"
    return f"{name}: {shortened(headline, MAX_TITLE_LENGTH - len(frame))} ({advisory})"


def remedy_of(name, ranges):
    fixes = sorted({item["fixed"] for item in ranges if "fixed" in item}, key=version_key)
    if not fixes:
        return f"No fixed {name} release is listed for this advisory. Upgrade each listed install to the newest supported {name} release and check the advisory."
    remedy = f"Upgrade {name} to {', '.join(fixes)} or a later release on the same line, in each listed install."
    if any("lastAffected" in item for item in ranges):
        remedy += f" For affected versions with no listed fix, upgrade to a later supported {name} release."
    return remedy if len(remedy) <= MAX_EXPLANATION_LENGTH else f"Upgrade {name} to a release after the affected versions listed in the advisory, in each listed install."


def references_of(record, advisory):
    candidates = [f"https://nvd.nist.gov/vuln/detail/{advisory}", f"https://osv.dev/vulnerability/{advisory}"]
    candidates += [field(reference, "url", str) for reference in field(record, "references", list)]
    references = []
    for url in candidates:
        if len(url) <= MAX_REFERENCE_LENGTH and REFERENCE_PATTERN.fullmatch(url) and url not in references:
            references.append(url)
    return references[:MAX_REFERENCES]


def category_of(record):
    cwes = {cwe for cwe in field(field(record, "database_specific", dict), "cwe_ids", list) if isinstance(cwe, str)}
    return "rce" if cwes & RCE_CWES or RCE_TEXT.search(clean_text(field(record, "details", str))) else "hardening"


def rule_problem(rule):
    if not RULE_ID_PATTERN.fullmatch(rule["id"]):
        return "invalid id"
    if not 1 <= len(rule["title"]) <= MAX_TITLE_LENGTH:
        return "title length"
    if rule["severity"] not in SEVERITIES or rule["product"] not in PRODUCTS:
        return "severity or product"
    if not ADVISORY_PATTERN.fullmatch(rule["advisory"]):
        return "invalid advisory"
    if not 1 <= len(rule["ranges"]) <= MAX_RANGES:
        return f"needs 1-{MAX_RANGES} ranges, has {len(rule['ranges'])}"
    if len(rule.get("summary", "")) > MAX_EXPLANATION_LENGTH or len(rule["remedy"]) > MAX_EXPLANATION_LENGTH:
        return "summary or remedy length"
    if len(rule["references"]) > MAX_REFERENCES:
        return "too many references"
    for item in rule["ranges"]:
        if any(stable_version(version, rule["product"]) != (version, False) for version in item.values()):
            return "version is not a release such as 1.2.3"
        start = version_key(item["introduced"])
        if ("fixed" in item) == ("lastAffected" in item):
            return "range needs exactly one of fixed or lastAffected"
        if "fixed" in item and not start < version_key(item["fixed"]):
            return "fixed is not after introduced"
        if "lastAffected" in item and not start <= version_key(item["lastAffected"]):
            return "lastAffected is before introduced"
    return None


def rule_from(record, product):
    advisory = field(record, "id", str)
    if not CVE_PATTERN.fullmatch(advisory):
        return None, "not a CVE record"
    if field(record, "withdrawn", str) or field(field(record, "database_specific", dict), "isDisputed", bool):
        return None, "withdrawn or disputed"
    ranges = extracted_ranges(record, product)
    if not ranges:
        return None, "no upstream version ranges"
    severity = severity_of(record)
    if severity is None:
        return None, "no severity"
    if SEVERITIES.index(severity) < SEVERITIES.index(MIN_SEVERITY):
        return None, f"below {MIN_SEVERITY}"
    name = PRODUCTS[product]["name"]
    rule = {
        "id": f"{ID_PREFIX}{product}.{advisory.lower()}",
        "title": title_of(record, name, advisory),
        "severity": severity,
        "category": category_of(record),
        "check": CHECK,
        "product": product,
        "advisory": advisory,
        "ranges": ranges,
        "summary": shortened(clean_text(field(record, "details", str)), MAX_EXPLANATION_LENGTH),
        "remedy": remedy_of(name, ranges),
        "references": references_of(record, advisory),
    }
    if not rule["summary"]:
        del rule["summary"]
    problem = rule_problem(rule)
    return (None, problem) if problem else (rule, None)


def output_key(rule):
    year, number = CVE_PATTERN.fullmatch(rule["advisory"]).groups()
    return list(PRODUCTS).index(rule["product"]), int(year), int(number)


def generated_rules():
    candidates = {}
    for product, settings in PRODUCTS.items():
        try:
            records = fetch_records(settings["repo"])
        except (OSError, ValueError, http.client.HTTPException) as error:
            fail(f"{product}: OSV query failed ({type(error).__name__}: {error})")
        skipped = {}
        for record in records:
            rule, reason = rule_from(record, product)
            if rule is None:
                skipped[reason] = skipped.get(reason, 0) + 1
                continue
            candidates[rule["id"]] = (rule, field(record, "published", str))
        emitted = sum(1 for rule, _ in candidates.values() if rule["product"] == product)
        log(f"{product}: {len(records)} OSV records, {emitted} rules, skipped {dict(sorted(skipped.items()))}")
    newest = sorted(candidates.values(), key=lambda item: output_key(item[0]))
    newest.sort(key=lambda item: item[1], reverse=True)
    chosen = sorted((rule for rule, _ in newest[:MAX_GENERATED_RULES]), key=output_key)
    if len(candidates) > MAX_GENERATED_RULES:
        kept = {product: sum(1 for rule in chosen if rule["product"] == product) for product in PRODUCTS}
        log(f"kept the {MAX_GENERATED_RULES} newest of {len(candidates)} rules: {kept}")
    return chosen


def is_generated(rule):
    return rule.get("check") == CHECK and str(rule.get("id", "")).startswith(ID_PREFIX)


def estimated_envelope_bytes(rulebook):
    payload = json.dumps({**rulebook, **STAMPED_FIELDS}, indent=2, sort_keys=True, separators=(",", " : "), ensure_ascii=False).encode()
    return 4 * math.ceil(len(payload) / 3) + ENVELOPE_OVERHEAD_BYTES


def main():
    with open(RULES_FILE, encoding="utf-8") as handle:
        rulebook = json.load(handle)
    kept = [rule for rule in rulebook["rules"] if not is_generated(rule)]
    generated = generated_rules()
    if not generated:
        fail("OSV gave no usable rules; rules.json left unchanged")
    rules = kept + generated
    ids = [rule["id"] for rule in rules]
    duplicates = sorted({rule_id for rule_id in ids if ids.count(rule_id) > 1})
    if duplicates:
        fail(f"rule ids used twice: {duplicates}")
    if len(rules) > MAX_RULES:
        fail(f"{len(rules)} rules is more than the app's {MAX_RULES}; lower MAX_GENERATED_RULES")
    rulebook["rules"] = rules
    size = estimated_envelope_bytes(rulebook)
    if size > MAX_ENVELOPE_BYTES:
        fail(f"the signed rules would be about {size} bytes, the app accepts {MAX_ENVELOPE_BYTES}; lower MAX_GENERATED_RULES")
    with open(RULES_FILE, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(rulebook, indent=2, ensure_ascii=False) + "\n")
    log(f"Wrote {RULES_FILE}: {len(kept)} other rules kept, {len(generated)} generated rules, signed size about {size} bytes")


if __name__ == "__main__":
    main()
