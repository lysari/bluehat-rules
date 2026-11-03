import importlib.util
import pathlib
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "update_cve_rules.py"
SPEC = importlib.util.spec_from_file_location("update_cve_rules", SCRIPT)
update_cve_rules = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(update_cve_rules)

CRITICAL_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def record_with(urls, repo="https://github.com/python/cpython"):
    versions = [{"introduced": "3.0.0"}, {"fixed": "3.1.0"}]
    return {
        "id": "CVE-2026-0001",
        "details": "A flaw.",
        "severity": [{"type": "CVSS_V3", "score": CRITICAL_VECTOR}],
        "affected": [{"ranges": [{"type": "GIT", "repo": repo, "database_specific": {"versions": versions}}]}],
        "references": [{"url": url} for url in urls],
    }


class AllowedReferenceTests(unittest.TestCase):
    def assert_allowed(self, url, product="python"):
        self.assertTrue(update_cve_rules.is_allowed_reference(url, product), url)

    def assert_rejected(self, url, product="python"):
        self.assertFalse(update_cve_rules.is_allowed_reference(url, product), url)

    def test_allows_the_public_vulnerability_databases_for_every_product(self):
        for product in update_cve_rules.PRODUCTS:
            self.assert_allowed("https://nvd.nist.gov/vuln/detail/CVE-2026-0001", product)
            self.assert_allowed("https://osv.dev/vulnerability/CVE-2026-0001", product)
            self.assert_allowed("https://www.cve.org/CVERecord?id=CVE-2026-0001", product)
            self.assert_allowed("https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-0001", product)
            self.assert_allowed("https://github.com/CVEProject/cvelistV5/tree/main/cves/2026", product)

    def test_allows_each_products_own_sites(self):
        self.assert_allowed("https://nodejs.org/en/blog/vulnerability/", "node")
        self.assert_allowed("https://github.com/nodejs/node/pull/1", "node")
        self.assert_allowed("https://bugs.php.net/bug.php?id=1", "php")
        self.assert_allowed("https://github.com/php/php-src/security/advisories/GHSA-1", "php")
        self.assert_allowed("https://mail.python.org/archives/list/security-announce@python.org/thread/1/", "python")
        self.assert_allowed("https://github.com/python/cpython/issues/1", "python")
        self.assert_allowed("https://git.openssl.org/gitweb/?p=openssl.git", "openssl")
        self.assert_allowed("https://openssl-library.org/news/secadv/20260101.txt", "openssl")
        self.assert_allowed("https://github.com/openssl/openssl/commit/abc", "openssl")
        self.assert_allowed("https://git-scm.com/docs/git-clone", "git")
        self.assert_allowed("https://github.com/git/git/compare/v2.1.0..v2.2.0", "git")
        self.assert_allowed("https://git.kernel.org/pub/scm/git/git.git/tree/README.md", "git")
        self.assert_allowed("https://lore.kernel.org/git/1@example.net", "git")
        self.assert_allowed("https://www.ruby-lang.org/en/news/", "ruby")
        self.assert_allowed("https://github.com/ruby/ruby/pull/1", "ruby")

    def test_host_case_and_github_owner_case_do_not_matter(self):
        self.assert_allowed("https://WWW.Python.ORG/downloads/")
        self.assert_allowed("https://github.com/Python/cpython/issues/1")
        self.assert_allowed("https://github.com/cveproject/cvelistV5")

    def test_rejects_hosts_that_only_look_like_an_allowed_one(self):
        self.assert_rejected("https://python.org.evil.com/")
        self.assert_rejected("https://notpython.org/")
        self.assert_rejected("https://evil-python.org/")
        self.assert_rejected("https://python.org./")
        self.assert_rejected("https://.python.org/")
        self.assert_rejected("https://evil..python.org/")
        self.assert_rejected("https://nist.gov/vuln/detail/CVE-2026-0001")
        self.assert_rejected("https://mitre.org/")
        self.assert_rejected("https://emudhra.we-have-a-problem.com/")

    def test_rejects_other_schemes(self):
        self.assert_rejected("http://python.org/")
        self.assert_rejected("HTTPS://python.org/")
        self.assert_rejected("ftp://python.org/")
        self.assert_rejected("javascript:alert(1)//python.org/")
        self.assert_rejected("//python.org/")

    def test_rejects_userinfo_ports_and_url_tricks(self):
        self.assert_rejected("https://python.org@evil.com")
        self.assert_rejected("https://python.org@evil.com/")
        self.assert_rejected("https://user:secret@python.org/")
        self.assert_rejected("https://evil.com@python.org/")
        self.assert_rejected("https://evil.com#@python.org/")
        self.assert_rejected("https://evil.com?@python.org/")
        self.assert_rejected("https://evil.com/@python.org/")
        self.assert_rejected("https://evil.com\\@python.org/")
        self.assert_rejected("https://python.org:8443/")
        self.assert_rejected("https://python.org:443/")
        self.assert_rejected("https://python.org:99999/")
        self.assert_rejected("https://evil.com/python.org")
        self.assert_rejected("https://evil.com/?u=https://python.org/")
        self.assert_rejected("https://py%74hon.org/")
        self.assert_rejected("https://pythön.org/")
        self.assert_rejected(" https://python.org/")
        self.assert_rejected("https://python.org/\n")

    def test_rejects_github_outside_the_covered_organisations(self):
        self.assert_rejected("https://github.com/")
        self.assert_rejected("https://github.com")
        self.assert_rejected("https://github.com/nu11secur1ty/CVE/blob/main/x")
        self.assert_rejected("https://github.com/python-evil/cpython")
        self.assert_rejected("https://github.com/pythonx/cpython")
        self.assert_rejected("https://github.com/python.evil/cpython")
        self.assert_rejected("https://github.com/evil/python/")
        self.assert_rejected("https://github.com//python/cpython")
        self.assert_rejected("https://github.com/p%79thon/cpython")
        self.assert_rejected("https://github.com/CVEProject-evil/x")
        self.assert_rejected("https://gist.github.com/python/1")
        self.assert_rejected("https://evil.github.com/python/1")
        self.assert_rejected("https://www.github.com/python/cpython")
        self.assert_rejected("https://python.github.io/x")
        self.assert_rejected("https://raw.githubusercontent.com/python/cpython/main/x")

    def test_rejects_paths_that_climb_out_of_an_allowed_organisation(self):
        self.assert_rejected("https://github.com/python/../evil/repo")
        self.assert_rejected("https://github.com/python/./../evil/repo")
        self.assert_rejected("https://github.com/python/%2e%2e/evil/repo")
        self.assert_rejected("https://github.com/python/.%2E/evil/repo")
        self.assert_rejected("https://github.com/python%2f..%2fevil/repo")
        self.assert_rejected("https://github.com/python/x%2F..%2F..%2Fevil")
        self.assert_rejected("https://github.com/python/%5c..%5cevil")
        self.assert_rejected("https://lore.kernel.org/git/../evil/1", "git")

    def test_rejects_shared_hosting_outside_the_covered_paths(self):
        self.assert_rejected("https://lore.kernel.org/linux-evil/1", "git")
        self.assert_rejected("https://lore.kernel.org/git-evil/1", "git")
        self.assert_rejected("https://lore.kernel.org/", "git")
        self.assert_rejected("https://sub.lore.kernel.org/git/1", "git")
        self.assert_rejected("https://kernel.org/", "git")
        self.assert_rejected("https://git.kernel.org/pub/scm/linux/kernel/git/evil", "git")
        self.assert_rejected("https://git.kernel.org/pub/scm/git-evil/x", "git")
        self.assert_rejected("https://hackerone.com/reports/1", "node")
        self.assert_rejected("https://python-security.readthedocs.io/security.html")
        self.assert_rejected("https://readthedocs.io/")

    def test_rejects_another_products_vendor(self):
        self.assert_rejected("https://git.openssl.org/gitweb/", "node")
        self.assert_rejected("https://www.openssl.org/news/", "node")
        self.assert_rejected("https://www.python.org/", "ruby")
        self.assert_rejected("https://github.com/python/cpython", "ruby")
        self.assert_rejected("https://lore.kernel.org/git/1", "python")

    def test_rejects_links_over_the_length_limit(self):
        base = "https://python.org/"
        limit = update_cve_rules.MAX_REFERENCE_LENGTH
        self.assert_allowed(base + "a" * (limit - len(base)))
        self.assert_rejected(base + "a" * (limit - len(base) + 1))


class RuleReferencesTests(unittest.TestCase):
    NVD = "https://nvd.nist.gov/vuln/detail/CVE-2026-0001"
    OSV = "https://osv.dev/vulnerability/CVE-2026-0001"

    def references_for(self, urls):
        rule, problem = update_cve_rules.rule_from(record_with(urls), "python")
        self.assertIsNone(problem)
        return rule["references"]

    def test_keeps_nvd_when_filtering_removes_every_record_link(self):
        urls = ["https://emudhra.we-have-a-problem.com/", "https://twitter.com/x", "https://python.org@evil.com"]
        self.assertEqual(self.references_for(urls), [self.NVD, self.OSV])

    def test_a_record_with_no_links_still_gets_nvd(self):
        self.assertEqual(self.references_for([]), [self.NVD, self.OSV])

    def test_a_rejected_link_does_not_use_up_the_limit(self):
        rejected = [f"https://evil.example/{index}" for index in range(10)]
        allowed = [f"https://www.python.org/{index}" for index in range(10)]
        references = self.references_for(rejected + allowed)
        self.assertEqual(references, [self.NVD, self.OSV, *allowed[:3]])
        self.assertEqual(len(references), update_cve_rules.MAX_REFERENCES)

    def test_a_repeated_link_is_listed_once(self):
        self.assertEqual(self.references_for([self.NVD, "https://www.python.org/", "https://www.python.org/"]), [self.NVD, self.OSV, "https://www.python.org/"])

    def test_a_rule_with_no_references_is_refused(self):
        rule, _ = update_cve_rules.rule_from(record_with([]), "python")
        self.assertEqual(update_cve_rules.rule_problem({**rule, "references": []}), "needs 1-5 references, has 0")
