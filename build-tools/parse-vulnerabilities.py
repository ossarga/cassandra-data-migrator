#!/usr/bin/env python3
"""
parse-vulnerabilities.py

Reads a Trivy vulnerability JSON report and produces update JSON files and
plain-text remediation reports for two vulnerability classes:

Java (lang-pkgs / Target: "Java")
----------------------------------
  Output JSON: same schema as spark-update-dependencies.json.
    { "name": str, "group": str, "versions": { "old": str, "new": str } }

  Report sections:
    A — Direct dependencies with no fix available yet.
    B — Indirect (shaded) dependencies where the outer JAR was resolved to a
        newer version on Maven Central (or where no upgrade exists).
    C — Indirect dependencies skipped via --skip-prefixes.
    D — Indirect dependencies where resolution failed.
    E — Direct dependencies where the Trivy-recommended version is not
        published on Maven Central and no safe fallback could be found.

OS packages (os-pkgs / Target: alpine/debian/etc.)
----------------------------------------------------
  Output JSON: same schema as the Java output but with "group" always set to
  the empty string, since Alpine apk packages have no Maven group concept.
    { "name": str, "group": "", "versions": { "old": str, "new": str } }

  Report sections:
    A — OS packages with no fix available yet.

Direct version availability checking (Java only)
-------------------------------------------------
When --resolve-direct is passed, the script verifies that the Trivy-recommended
fixed version actually exists on Maven Central before writing it to the output
JSON.  If the version is not published (a common occurrence where Trivy's
vulnerability database references a patch that was never released to Central),
the script falls back to the following resolution:

  Step 1 — Enumerate all published versions from maven-metadata.xml for the
    affected package.

  Step 2 — For each candidate version >= the Trivy-recommended version,
    query the OSV.dev public API (api.osv.dev) to check whether that version
    has any known vulnerabilities.  Candidates are tested in descending
    version order so the highest clean version is selected first.

  Step 3 — If a clean candidate is found it replaces the Trivy-recommended
    version in the output JSON.  If no clean candidate exists the package is
    written to Section E of the report for manual review.

  OSV.dev is the same vulnerability database that Trivy uses as a backend.
  No authentication is required.

Indirect dependency resolution (Java only)
------------------------------------------
When --resolve-indirect is passed, the script attempts to automatically resolve
the outer JAR to a newer version on Maven Central using the following two-step
approach:

  Step 1 — Group resolution via Maven Search API
    Query https://search.maven.org/solrsearch/select?q=a:<artifact> to find
    the Maven group ID for the outer JAR.  The correct candidate is identified
    by confirming that the installed version exists in that group's version list
    on Maven Central (step 2 below).  This guards against selecting a fork or
    an unrelated artifact that happens to share the same name.

  Step 2 — Version list via Maven Central metadata
    Fetch https://repo1.maven.org/maven2/<group>/<artifact>/maven-metadata.xml
    and parse all available versions.  The latest version within the same major
    version series as the installed version is selected as the upgrade target.
    Staying within the same major avoids breaking API changes (e.g. jline 3.x
    would not be upgraded to 4.x automatically).

  Outer JARs whose filename prefix matches any entry in --skip-prefixes are
  excluded from resolution and written to the report instead.  Use this for
  self-built JARs (e.g. cassandra-data-migrator) and project-level JARs
  (e.g. spark-) where the correct remediation is a source-level dependency
  bump and rebuild rather than a drop-in JAR replacement.

  If resolution fails for any reason (network error, no newer version found,
  ambiguous search results), the outer JAR is written to the report with the
  failure reason noted.
"""

import argparse
import json
import os
import re
import sys
import typing
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

class JarUpdateEntry(typing.TypedDict):
    """A single entry in the Java dependency-update output JSON.

    Mirrors the spark-update-dependencies.json schema:
      { "name": str, "group": str, "versions": { "old": str, "new": str } }
    """
    name: str
    group: str
    versions: dict  # {"old": str, "new": str}


class OsUpdateEntry(typing.TypedDict):
    """A single entry in the OS package update output JSON.

    Uses the same schema as JarUpdateEntry but "group" is always "".
    Alpine apk packages have no Maven group concept.
      { "name": str, "group": "", "versions": { "old": str, "new": str } }
    """
    name: str
    versions: dict  # {"old": str, "new": str}


class JarVulnerabilityDetail(typing.TypedDict):
    """Detail record for a Java vulnerability (has pkg_path)."""
    vulnerability_id: str
    pkg_name: str
    pkg_path: str
    installed_version: str
    fixed_version: str
    status: str
    severity: str
    title: str
    primary_url: str


class OsVulnerabilityDetail(typing.TypedDict):
    """Detail record for an OS package vulnerability (no pkg_path)."""
    vulnerability_id: str
    pkg_name: str
    installed_version: str
    fixed_version: str
    status: str
    severity: str
    title: str
    primary_url: str


class OuterJarResolution(typing.TypedDict):
    jar_filename: str
    group: str
    artifact: str
    installed_version: str
    new_version: str           # empty string when no newer version is available
    classifier: str            # e.g. 'jdk8', empty string if none
    resolution_note: str       # human-readable outcome summary
    vulns: list                # list[JarVulnerabilityDetail]


class UnresolvableDirectDep(typing.TypedDict):
    """A direct dependency whose Trivy-recommended version is absent from Maven
    Central and for which no clean fallback version could be found via OSV.dev.
    Written to Section E of the remediation report."""
    pkg_name: str          # full group:artifact string
    group: str
    name: str              # artifact only
    installed_version: str
    trivy_fixed_version: str   # what Trivy recommended (not on Central)
    candidates_checked: list   # [(version, vuln_count), ...] — versions tried
    note: str                  # human-readable outcome summary


# ---------------------------------------------------------------------------
# Maven resolver
# ---------------------------------------------------------------------------

# Matches the version portion of a JAR filename.
# Handles: name-1.2.3.jar, name-1.2.3-jdk8.jar, name_2.13-1.2.3.jar
_JAR_VERSION_RE = re.compile(
    r'-(\d+\.\d[\d.]*)(?:-([a-zA-Z][a-zA-Z0-9]*))?\.jar$'
)
_SCALA_SUFFIX_RE = re.compile(r'_\d+\.\d+$')
_XML_VERSION_RE = re.compile(r'<version>([^<]+)</version>')


def _version_key(version: str) -> list:
    """Return a sortable key for a version string.

    Numeric segments sort numerically; non-numeric segments sort
    lexicographically and after numeric segments of the same position.
    """
    def coerce(part: str):
        try:
            return (0, int(part))
        except ValueError:
            return (1, part)

    return [coerce(p) for p in re.split(r'[.\-]', version)]


class MavenOuterJarResolver:
    """Resolves an outer (shading) JAR to a newer version on Maven Central."""

    _SEARCH_URL = 'https://search.maven.org/solrsearch/select'
    _METADATA_URL = 'https://repo1.maven.org/maven2/{group_path}/{artifact}/maven-metadata.xml'

    def __init__(self, timeout: int = 20) -> None:
        self._timeout = timeout

    # ------------------------------------------------------------------
    # Filename parsing
    # ------------------------------------------------------------------

    @staticmethod
    def parse_jar_filename(jar_filename: str) -> tuple[str, str, str] | None:
        """Return (artifact_id, version, classifier) or None if unparseable.

        The classifier (e.g. 'jdk8') is extracted when present.
        Scala suffixes (e.g. '_2.13') are stripped from the artifact name.
        """
        m = _JAR_VERSION_RE.search(jar_filename)
        if not m:
            return None
        version = m.group(1)
        classifier = m.group(2) or ''
        stem = jar_filename[:m.start()]
        artifact = _SCALA_SUFFIX_RE.sub('', stem)
        return artifact, version, classifier

    # ------------------------------------------------------------------
    # Network helpers
    # ------------------------------------------------------------------

    def _search_by_artifact(self, artifact: str) -> list[dict]:
        """Query Maven Search API and return the list of matching documents."""
        url = (
            f'{self._SEARCH_URL}'
            f'?q=a:{urllib.parse.quote(artifact)}&rows=10&wt=json'
        )
        with urllib.request.urlopen(url, timeout=self._timeout) as resp:
            data = json.loads(resp.read())
        return data.get('response', {}).get('docs', [])

    def _get_versions(self, group: str, artifact: str) -> list[str]:
        """Fetch all versions of group:artifact from Maven Central metadata."""
        group_path = group.replace('.', '/')
        url = self._METADATA_URL.format(group_path=group_path, artifact=artifact)
        with urllib.request.urlopen(url, timeout=self._timeout) as resp:
            content = resp.read().decode()
        return list(dict.fromkeys(_XML_VERSION_RE.findall(content)))

    # ------------------------------------------------------------------
    # Version selection
    # ------------------------------------------------------------------

    @staticmethod
    def _same_major_latest(installed: str, all_versions: list[str]) -> str | None:
        """Return the latest version in the same major series as *installed*.

        Staying within the same major avoids silent breaking API changes.
        Returns None if no newer same-major version exists.
        """
        installed_key = _version_key(installed)
        installed_major = installed_key[0]

        candidates = [
            v for v in all_versions
            if _version_key(v)[0] == installed_major
            and _version_key(v) > installed_key
        ]
        if not candidates:
            return None
        return sorted(candidates, key=_version_key)[-1]

    # ------------------------------------------------------------------
    # Public resolution entry point
    # ------------------------------------------------------------------

    def resolve(self, jar_filename: str, vulns: list) -> OuterJarResolution:
        """Attempt to resolve *jar_filename* to a newer Maven Central version.

        Returns an OuterJarResolution whose new_version is an empty string
        when no upgrade is available or resolution fails.
        """
        parsed = self.parse_jar_filename(jar_filename)
        if parsed is None:
            return OuterJarResolution(
                jar_filename=jar_filename,
                group='', artifact='', installed_version='', new_version='',
                classifier='',
                resolution_note='Could not parse version from filename.',
                vulns=vulns,
            )

        artifact, version, classifier = parsed

        # Step 1 — find the Maven group
        try:
            candidates = self._search_by_artifact(artifact)
        except Exception as exc:
            return OuterJarResolution(
                jar_filename=jar_filename,
                group='', artifact=artifact, installed_version=version,
                new_version='', classifier=classifier,
                resolution_note=f'Maven Search API error: {exc}',
                vulns=vulns,
            )

        if not candidates:
            return OuterJarResolution(
                jar_filename=jar_filename,
                group='', artifact=artifact, installed_version=version,
                new_version='', classifier=classifier,
                resolution_note='No results from Maven Search API.',
                vulns=vulns,
            )

        # Step 2 — confirm group by checking the installed version is in its
        # version list, then pick the latest same-major upgrade
        for candidate in candidates:
            group = candidate.get('g', '')
            try:
                all_versions = self._get_versions(group, artifact)
            except Exception:
                continue

            if version not in all_versions:
                continue  # not the right group for this JAR

            new_version = self._same_major_latest(version, all_versions)

            if new_version is None:
                note = (
                    f'Resolved to {group}:{artifact}. '
                    f'No newer version in the {version.split(".")[0]}.x series '
                    f'(latest on Central: {all_versions[-1]}).'
                )
            else:
                note = f'Resolved to {group}:{artifact}. Upgrade {version} -> {new_version}.'

            return OuterJarResolution(
                jar_filename=jar_filename,
                group=group, artifact=artifact,
                installed_version=version,
                new_version=new_version or '',
                classifier=classifier,
                resolution_note=note,
                vulns=vulns,
            )

        # No candidate's version list contained the installed version
        groups_tried = [c.get('g', '') for c in candidates]
        return OuterJarResolution(
            jar_filename=jar_filename,
            group='', artifact=artifact, installed_version=version,
            new_version='', classifier=classifier,
            resolution_note=(
                f'Could not confirm group for {artifact}@{version}. '
                f'Candidates tried: {groups_tried}.'
            ),
            vulns=vulns,
        )


# ---------------------------------------------------------------------------
# Direct version availability checker and OSV.dev client
# ---------------------------------------------------------------------------

class OsvClient:
    """Queries the OSV.dev public API for known vulnerabilities.

    OSV.dev is free, requires no authentication, and uses the same underlying
    vulnerability data that Trivy uses.  A query for a specific (package,
    version) pair returns the list of vulnerabilities affecting that version.
    An empty list means the version is clean.
    """

    _QUERY_URL = 'https://api.osv.dev/v1/query'

    def __init__(self, timeout: int = 20) -> None:
        self._timeout = timeout

    def vuln_count(self, group: str, artifact: str, version: str) -> int:
        """Return the number of known vulnerabilities for group:artifact@version.

        Returns -1 if the query fails, so callers can distinguish a network
        error from a genuinely clean version (0).
        """
        payload = json.dumps({
            'package': {
                'name': f'{group}:{artifact}',
                'ecosystem': 'Maven',
            },
            'version': version,
        }).encode()
        req = urllib.request.Request(
            self._QUERY_URL,
            data=payload,
            headers={'Content-Type': 'application/json'},
            method='POST',
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                data = json.loads(resp.read())
            return len(data.get('vulns', []))
        except Exception:
            return -1


class MavenJarAvailabilityChecker:
    """Checks whether a specific JAR version exists on Maven Central and, when
    it does not, enumerates all published versions from maven-metadata.xml so
    that a safe fallback can be selected."""

    _JAR_URL = (
        'https://repo1.maven.org/maven2/'
        '{group_path}/{artifact}/{version}/{artifact}-{version}.jar'
    )
    _METADATA_URL = (
        'https://repo1.maven.org/maven2/'
        '{group_path}/{artifact}/maven-metadata.xml'
    )

    def __init__(self, timeout: int = 20) -> None:
        self._timeout = timeout

    def exists(self, group: str, artifact: str, version: str) -> bool:
        """Return True if the JAR for group:artifact:version is on Maven Central."""
        group_path = group.replace('.', '/')
        url = self._JAR_URL.format(
            group_path=group_path, artifact=artifact, version=version
        )
        req = urllib.request.Request(url, method='HEAD')
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                return resp.status == 200
        except urllib.error.HTTPError as e:
            return e.code != 404
        except Exception:
            return False

    def published_versions(self, group: str, artifact: str) -> list[str]:
        """Return all versions listed in maven-metadata.xml, in the order they
        appear (oldest to newest as Maven publishes them)."""
        group_path = group.replace('.', '/')
        url = self._METADATA_URL.format(group_path=group_path, artifact=artifact)
        try:
            with urllib.request.urlopen(url, timeout=self._timeout) as resp:
                content = resp.read().decode()
            return list(dict.fromkeys(_XML_VERSION_RE.findall(content)))
        except Exception:
            return []


class DirectVersionResolver:
    """Resolves a direct JAR dependency to a downloadable, vulnerability-free
    version on Maven Central when the Trivy-recommended version is absent.

    Resolution algorithm:
      1. HEAD-check the Trivy-recommended version.  If it exists, return it
         immediately — no further work needed.
      2. Fetch maven-metadata.xml and collect all published versions >=
         the Trivy-recommended version.
      3. Query OSV.dev for each candidate in descending version order.
         Return the first version with zero known vulnerabilities.
      4. If no clean candidate exists, return None so the caller can record
         the package in the Section E report.
    """

    def __init__(self, timeout: int = 20) -> None:
        self._checker = MavenJarAvailabilityChecker(timeout=timeout)
        self._osv = OsvClient(timeout=timeout)

    def resolve(
        self,
        group: str,
        artifact: str,
        trivy_version: str,
    ) -> tuple[str | None, list[tuple[str, int]]]:
        """Return (resolved_version, candidates_checked).

        resolved_version is the version to use:
          - The trivy_version itself if it exists on Maven Central.
          - The highest published version with zero OSV.dev vulnerabilities
            that is >= trivy_version, if the trivy_version is absent.
          - None if no suitable version could be found.

        candidates_checked is a list of (version, vuln_count) pairs for every
        version that was OSV-queried, in the order they were checked.
        -1 as vuln_count means the OSV query failed for that version.
        """
        # Step 1 — fast path: recommended version is on Maven Central
        if self._checker.exists(group, artifact, trivy_version):
            return trivy_version, []

        # Step 2 — enumerate published versions >= trivy_version
        all_versions = self._checker.published_versions(group, artifact)
        trivy_key = _version_key(trivy_version)
        candidates = sorted(
            [v for v in all_versions if _version_key(v) >= trivy_key],
            key=_version_key,
            reverse=True,  # highest first so we pick the best clean version
        )

        # Step 3 — OSV-check each candidate, return the first clean one
        checked: list[tuple[str, int]] = []
        for version in candidates:
            count = self._osv.vuln_count(group, artifact, version)
            checked.append((version, count))
            if count == 0:
                return version, checked

        # Step 4 — nothing clean found
        return None, checked


# ---------------------------------------------------------------------------
# Shared parsing helpers
# ---------------------------------------------------------------------------

def _latest_fixed_version(fixed_version_field: str) -> str:
    """Return the highest fixed version from a Trivy FixedVersion field.

    Trivy may report a comma-separated list (e.g. '2.18.8, 2.21.4' or
    '10.14.2.1, 10.16.1.2, 10.15.2.1').  The list is not guaranteed to be
    in ascending order, so all entries are compared using _version_key and
    the maximum is returned.
    """
    if not fixed_version_field:
        return ''
    parts = [p.strip() for p in fixed_version_field.split(',') if p.strip()]
    if not parts:
        return fixed_version_field.strip()
    return sorted(parts, key=_version_key)[-1]


# ---------------------------------------------------------------------------
# OS package parser
# ---------------------------------------------------------------------------

class OsVulnerabilityParser:
    """Parses the os-pkgs result from a Trivy JSON report.

    Produces:
      - A list of OsUpdateEntry items for packages whose status is "fixed",
        deduplicated by (name, installed_version).
      - A list of OsVulnerabilityDetail items for packages with no fix yet,
        for inclusion in the remediation report.
    """

    OS_CLASS = 'os-pkgs'

    def __init__(self, vuln_json_path: str) -> None:
        self._vuln_json_path = vuln_json_path
        self._vulnerabilities: list[dict] = []
        self._source_image: str = ''

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _load(self) -> None:
        with open(self._vuln_json_path, 'r') as fh:
            data = json.load(fh)

        self._source_image = data.get('ArtifactName', os.path.basename(self._vuln_json_path))

        os_result = next(
            (r for r in data.get('Results', []) if r.get('Class') == self.OS_CLASS),
            None,
        )
        if os_result is None:
            raise ValueError(
                f'No result with Class="{self.OS_CLASS}" found in {self._vuln_json_path}'
            )

        self._vulnerabilities = os_result.get('Vulnerabilities') or []

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------

    def _classify(self) -> tuple[
        list[OsUpdateEntry],          # fixed  -> output JSON
        list[OsVulnerabilityDetail],  # not fixed -> report section A
    ]:
        update_map: dict[tuple[str, str], OsUpdateEntry] = {}
        not_fixed: list[OsVulnerabilityDetail] = []

        for vuln in self._vulnerabilities:
            pkg_name: str = vuln.get('PkgName', '')
            installed: str = vuln.get('InstalledVersion', '')
            fixed_raw: str = vuln.get('FixedVersion') or ''
            status: str = vuln.get('Status', '')

            detail: OsVulnerabilityDetail = {
                'vulnerability_id': vuln.get('VulnerabilityID', ''),
                'pkg_name': pkg_name,
                'installed_version': installed,
                'fixed_version': fixed_raw,
                'status': status,
                'severity': vuln.get('Severity', ''),
                'title': vuln.get('Title', ''),
                'primary_url': vuln.get('PrimaryURL', ''),
            }

            if status == 'fixed':
                key = (pkg_name, installed)
                if key not in update_map:
                    update_map[key] = OsUpdateEntry(
                        name=pkg_name,
                        versions={
                            'old': installed,
                            'new': _latest_fixed_version(fixed_raw),
                        },
                    )
            else:
                not_fixed.append(detail)

        return list(update_map.values()), not_fixed

    # ------------------------------------------------------------------
    # Report writing
    # ------------------------------------------------------------------

    @staticmethod
    def _format_detail_block(detail: OsVulnerabilityDetail) -> str:
        lines = [
            f"  Vulnerability ID : {detail['vulnerability_id']}",
            f"  Severity         : {detail['severity']}",
            f"  Package          : {detail['pkg_name']}",
            f"  Installed        : {detail['installed_version']}",
            f"  Fixed Version    : {detail['fixed_version'] or '(none available)'}",
            f"  Status           : {detail['status']}",
            f"  Title            : {detail['title']}",
            f"  URL              : {detail['primary_url']}",
        ]
        return '\n'.join(lines)

    def _write_report(
        self,
        report_path: str,
        not_fixed: list[OsVulnerabilityDetail],
    ) -> None:
        timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        lines: list[str] = [
            '=' * 72,
            'OS Package Vulnerability Remediation Report',
            f'Generated : {timestamp}',
            f'Source    : {self._source_image}',
            '=' * 72,
            '',
            'SECTION A — OS Packages: No Fix Available',
            '-' * 72,
            'These Alpine apk packages have no fixed version released yet.',
            'Monitor these CVEs and update once a fix becomes available.',
            '',
        ]
        if not_fixed:
            for detail in not_fixed:
                lines.append(self._format_detail_block(detail))
                lines.append('')
        else:
            lines += ['  (none)', '']

        lines += ['=' * 72]

        with open(report_path, 'w') as fh:
            fh.write('\n'.join(lines) + '\n')

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(
        self,
        output_json_path: str,
        report_path: str,
    ) -> None:
        self._load()
        os_updates, not_fixed = self._classify()

        with open(output_json_path, 'w') as fh:
            json.dump(os_updates, fh, indent=2)

        print(f'\nOS output JSON written to: {output_json_path}')
        print(f'  Fixed updates  : {len(os_updates)}')

        self._write_report(report_path, not_fixed)
        print(f'OS report written to: {report_path}')
        print(f'  Section A (no fix) : {len(not_fixed)}')


# ---------------------------------------------------------------------------
# Java vulnerability parser
# ---------------------------------------------------------------------------

class JarVulnerabilityParser:
    JAVA_TARGET = 'Java'

    def __init__(self, vuln_json_path: str) -> None:
        self._vuln_json_path = vuln_json_path
        self._vulnerabilities: list[dict] = []
        self._source_image: str = ''

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _load(self) -> None:
        with open(self._vuln_json_path, 'r') as fh:
            data = json.load(fh)

        self._source_image = data.get('ArtifactName', os.path.basename(self._vuln_json_path))

        java_result = next(
            (r for r in data.get('Results', []) if r.get('Target') == self.JAVA_TARGET),
            None
        )
        if java_result is None:
            raise ValueError(
                f'No result with Target="{self.JAVA_TARGET}" found in {self._vuln_json_path}'
            )

        self._vulnerabilities = java_result.get('Vulnerabilities') or []

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _split_pkg_name(pkg_name: str) -> tuple[str, str]:
        """Return (group, name) from 'group:name'.  Falls back to ('', pkg_name)."""
        if ':' in pkg_name:
            group, _, name = pkg_name.partition(':')
            return group, name
        return '', pkg_name

    @staticmethod
    def _jar_filename(pkg_path: str) -> str:
        """Return the bare filename component of a PkgPath value."""
        return pkg_path.split('/')[-1] if '/' in pkg_path else pkg_path

    @staticmethod
    def _latest_fixed_version(fixed_version_field: str) -> str:
        """Delegates to the module-level _latest_fixed_version helper."""
        return _latest_fixed_version(fixed_version_field)

    @staticmethod
    def _is_skipped(jar_filename: str, skip_prefixes: list[str]) -> bool:
        return any(jar_filename.startswith(prefix) for prefix in skip_prefixes)

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------

    def _classify(
        self,
        skip_prefixes: list[str],
        resolve_direct: bool,
        resolver_timeout: int,
    ) -> tuple[
        list[JarUpdateEntry],          # direct + fixed  -> output JSON
        list[JarVulnerabilityDetail],  # direct + not fixed -> report section A
        dict[str, list],               # outer_jar -> [JarVulnerabilityDetail] -> section B
        dict[str, list],               # outer_jar -> [JarVulnerabilityDetail] -> section C (skipped)
        list[UnresolvableDirectDep],   # direct + no safe version found -> section E
    ]:
        direct_map: dict[tuple[str, str], JarUpdateEntry] = {}
        not_fixed: list[JarVulnerabilityDetail] = []
        indirect_resolvable: dict[str, list] = {}
        indirect_skipped: dict[str, list] = {}
        unresolvable_direct: list[UnresolvableDirectDep] = []

        direct_resolver = DirectVersionResolver(timeout=resolver_timeout) if resolve_direct else None

        for vuln in self._vulnerabilities:
            pkg_name_full: str = vuln.get('PkgName', '')
            pkg_path: str = vuln.get('PkgPath', '')
            installed: str = vuln.get('InstalledVersion', '')
            fixed_raw: str = vuln.get('FixedVersion') or ''
            status: str = vuln.get('Status', '')

            group, pkg_name = self._split_pkg_name(pkg_name_full)
            jar_filename = self._jar_filename(pkg_path)
            is_direct = pkg_name in jar_filename

            detail: JarVulnerabilityDetail = {
                'vulnerability_id': vuln.get('VulnerabilityID', ''),
                'pkg_name': pkg_name_full,
                'pkg_path': pkg_path,
                'installed_version': installed,
                'fixed_version': fixed_raw,
                'status': status,
                'severity': vuln.get('Severity', ''),
                'title': vuln.get('Title', ''),
                'primary_url': vuln.get('PrimaryURL', ''),
            }

            if is_direct:
                if status == 'fixed':
                    key = (pkg_name, installed)
                    trivy_version = self._latest_fixed_version(fixed_raw)

                    if key not in direct_map:
                        if direct_resolver is not None:
                            print(
                                f'  Checking {pkg_name_full}@{trivy_version} ...',
                                end=' ', flush=True,
                            )
                            resolved_version, candidates = direct_resolver.resolve(
                                group, pkg_name, trivy_version
                            )
                            if resolved_version is None:
                                # No clean version available — record for Section E
                                print(f'-> no safe version found')
                                unresolvable_direct.append(UnresolvableDirectDep(
                                    pkg_name=pkg_name_full,
                                    group=group,
                                    name=pkg_name,
                                    installed_version=installed,
                                    trivy_fixed_version=trivy_version,
                                    candidates_checked=candidates,
                                    note=(
                                        f'Trivy recommended {trivy_version} but it is not '
                                        f'published on Maven Central.  No clean fallback found '
                                        f'among {len(candidates)} candidate(s) checked.'
                                    ),
                                ))
                                continue  # do not add to direct_map
                            elif resolved_version != trivy_version:
                                print(f'-> fallback to {resolved_version}')
                            else:
                                print(f'-> ok')
                            effective_version = resolved_version
                        else:
                            effective_version = trivy_version

                        direct_map[key] = JarUpdateEntry(
                            name=pkg_name,
                            group=group,
                            versions={
                                'old': installed,
                                'new': effective_version,
                            }
                        )
                    else:
                        # A later CVE entry may reference a higher fixed version —
                        # keep the highest seen across all CVEs for this package.
                        existing_new = direct_map[key]['versions']['new']
                        if _version_key(trivy_version) > _version_key(existing_new):
                            direct_map[key]['versions']['new'] = trivy_version
                else:
                    not_fixed.append(detail)
            else:
                if self._is_skipped(jar_filename, skip_prefixes):
                    indirect_skipped.setdefault(jar_filename, []).append(detail)
                else:
                    indirect_resolvable.setdefault(jar_filename, []).append(detail)

        return (
            list(direct_map.values()),
            not_fixed,
            indirect_resolvable,
            indirect_skipped,
            unresolvable_direct,
        )

    # ------------------------------------------------------------------
    # Report writing
    # ------------------------------------------------------------------

    @staticmethod
    def _format_detail_block(detail: JarVulnerabilityDetail) -> str:
        lines = [
            f"  Vulnerability ID : {detail['vulnerability_id']}",
            f"  Severity         : {detail['severity']}",
            f"  Package          : {detail['pkg_name']}",
            f"  Path             : {detail['pkg_path']}",
            f"  Installed        : {detail['installed_version']}",
            f"  Fixed Version    : {detail['fixed_version'] or '(none available)'}",
            f"  Status           : {detail['status']}",
            f"  Title            : {detail['title']}",
            f"  URL              : {detail['primary_url']}",
        ]
        return '\n'.join(lines)

    def _write_report(
        self,
        report_path: str,
        not_fixed: list[JarVulnerabilityDetail],
        resolved: list[OuterJarResolution],
        unresolved: list[OuterJarResolution],
        skipped: dict[str, list],
        unresolvable_direct: list[UnresolvableDirectDep],
    ) -> None:
        timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        lines: list[str] = [
            '=' * 72,
            'Vulnerability Remediation Report',
            f'Generated : {timestamp}',
            f'Source    : {self._source_image}',
            '=' * 72,
            '',
        ]

        # Section A — direct deps with no fix available
        lines += [
            'SECTION A — Direct Dependencies: No Fix Available',
            '-' * 72,
            'These packages have a direct JAR file in the image but no fixed',
            'version has been released yet.  Monitor these CVEs and update',
            'once a fix becomes available.',
            '',
        ]
        if not_fixed:
            for detail in not_fixed:
                lines.append(self._format_detail_block(detail))
                lines.append('')
        else:
            lines += ['  (none)', '']

        # Section B — indirect deps successfully resolved to a new outer JAR
        lines += [
            'SECTION B — Indirect Dependencies: Outer JAR Upgrade Available',
            '-' * 72,
            'These packages are bundled inside a shading JAR.  A newer version',
            'of the outer JAR has been found on Maven Central and added to the',
            'output dependency-update JSON.',
            '',
        ]
        b_with_upgrade = [r for r in resolved if r['new_version']]
        b_no_upgrade = [r for r in resolved if not r['new_version']]

        if b_with_upgrade:
            for res in b_with_upgrade:
                lines.append(f"  Outer JAR  : {res['jar_filename']}")
                lines.append(f"  Resolution : {res['resolution_note']}")
                lines.append(f"  Classifier : {res['classifier'] or '(none)'}")
                lines.append('  Vulnerabilities in this JAR:')
                for detail in res['vulns']:
                    lines.append(self._format_detail_block(detail))
                lines.append('')
        else:
            lines += ['  (none)', '']

        # Section B (continued) — resolved but no newer version
        if b_no_upgrade:
            lines += [
                '  -- No Upgrade Available (already at latest in series) --',
                '',
            ]
            for res in b_no_upgrade:
                lines.append(f"  Outer JAR  : {res['jar_filename']}")
                lines.append(f"  Resolution : {res['resolution_note']}")
                for detail in res['vulns']:
                    lines.append(self._format_detail_block(detail))
                lines.append('')

        # Section C — indirect deps that were skipped (prefix match)
        lines += [
            'SECTION C — Indirect Dependencies: Skipped (prefix match)',
            '-' * 72,
            'These outer JARs matched a --skip-prefixes entry.  They are',
            'excluded from automatic resolution.  The correct remediation is',
            'a source-level dependency bump and rebuild of the outer project.',
            '',
        ]
        if skipped:
            for jar_filename, details in sorted(skipped.items()):
                lines.append(f'  Outer JAR: {jar_filename}')
                lines.append('  ' + '-' * 68)
                for detail in details:
                    lines.append(self._format_detail_block(detail))
                    lines.append('')
        else:
            lines += ['  (none)', '']

        # Section D — indirect deps resolution failed
        lines += [
            'SECTION D — Indirect Dependencies: Resolution Failed',
            '-' * 72,
            'These outer JARs could not be automatically resolved.  Review',
            'the resolution note for each and handle manually.',
            '',
        ]
        if unresolved:
            for res in unresolved:
                lines.append(f"  Outer JAR  : {res['jar_filename']}")
                lines.append(f"  Resolution : {res['resolution_note']}")
                for detail in res['vulns']:
                    lines.append(self._format_detail_block(detail))
                lines.append('')
        else:
            lines += ['  (none)', '']

        # Section E — direct deps with no safe version on Maven Central
        lines += [
            'SECTION E — Direct Dependencies: No Safe Version on Maven Central',
            '-' * 72,
            'The Trivy-recommended fixed version for these packages is not',
            'published on Maven Central.  No published version with zero known',
            'vulnerabilities could be found.  Manual remediation is required.',
            '',
        ]
        if unresolvable_direct:
            for entry in unresolvable_direct:
                lines.append(f"  Package          : {entry['pkg_name']}")
                lines.append(f"  Installed        : {entry['installed_version']}")
                lines.append(f"  Trivy recommends : {entry['trivy_fixed_version']}  (not on Maven Central)")
                if entry['candidates_checked']:
                    lines.append('  Candidates checked (version : known vulns):')
                    for ver, count in entry['candidates_checked']:
                        count_str = str(count) if count >= 0 else 'query failed'
                        lines.append(f'    {ver} : {count_str}')
                else:
                    lines.append('  Candidates checked: none (maven-metadata.xml unavailable)')
                lines.append(f"  Note             : {entry['note']}")
                lines.append('')
        else:
            lines += ['  (none)', '']

        lines += ['=' * 72]

        with open(report_path, 'w') as fh:
            fh.write('\n'.join(lines) + '\n')

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(
        self,
        output_json_path: str,
        report_path: str,
        resolve_direct: bool,
        resolve_indirect: bool,
        skip_prefixes: list[str],
        resolver_timeout: int,
    ) -> None:
        self._load()
        direct_updates, not_fixed, indirect_resolvable, indirect_skipped, unresolvable_direct = \
            self._classify(skip_prefixes, resolve_direct, resolver_timeout)

        resolved: list[OuterJarResolution] = []
        unresolved: list[OuterJarResolution] = []
        outer_jar_updates: list[JarUpdateEntry] = []

        if resolve_indirect and indirect_resolvable:
            resolver = MavenOuterJarResolver(timeout=resolver_timeout)
            for jar_filename, vulns in sorted(indirect_resolvable.items()):
                print(f'  Resolving {jar_filename} ...', end=' ', flush=True)
                resolution = resolver.resolve(jar_filename, vulns)
                if resolution['new_version']:
                    resolved.append(resolution)
                    outer_jar_updates.append(JarUpdateEntry(
                        name=resolution['artifact'],
                        group=resolution['group'],
                        versions={
                            'old': resolution['installed_version'],
                            'new': resolution['new_version'],
                        }
                    ))
                    print(f"-> {resolution['new_version']}")
                elif resolution['group']:
                    # Group was resolved but no newer version exists
                    resolved.append(resolution)
                    print(f"-> no upgrade available ({resolution['resolution_note']})")
                else:
                    unresolved.append(resolution)
                    print(f"-> unresolved ({resolution['resolution_note']})")
        elif not resolve_indirect and indirect_resolvable:
            # Treat all indirect as unresolved when --resolve-indirect not given
            for jar_filename, vulns in sorted(indirect_resolvable.items()):
                unresolved.append(OuterJarResolution(
                    jar_filename=jar_filename,
                    group='', artifact='', installed_version='', new_version='',
                    classifier='',
                    resolution_note='Pass --resolve-indirect to attempt automatic resolution.',
                    vulns=vulns,
                ))

        all_updates = direct_updates + outer_jar_updates
        with open(output_json_path, 'w') as fh:
            json.dump(all_updates, fh, indent=2)

        print(f'\nOutput JSON written to: {output_json_path}')
        print(f'  Direct updates         : {len(direct_updates)}')
        print(f'  Outer JAR updates      : {len(outer_jar_updates)}')
        print(f'  Total entries          : {len(all_updates)}')

        self._write_report(
            report_path, not_fixed, resolved, unresolved, indirect_skipped, unresolvable_direct
        )
        print(f'\nReport written to: {report_path}')
        print(f'  Section A (direct, no fix)           : {len(not_fixed)}')
        print(f'  Section B (indirect, resolved)       : {len(resolved)}')
        print(f'  Section C (indirect, skipped)        : {sum(len(v) for v in indirect_skipped.values())} vulnerabilities across {len(indirect_skipped)} JAR(s)')
        print(f'  Section D (indirect, unresolved)     : {len(unresolved)}')
        print(f'  Section E (direct, no safe version)  : {len(unresolvable_direct)}')


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

class ParseVulnerabilities:
    @staticmethod
    def _parse_args() -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description=(
                'Parse a Trivy vulnerability JSON report and produce:\n'
                '  • A Java dependency-update JSON\n'
                '  • An OS package update JSON\n'
                '  • A Java remediation report\n'
                '  • An OS package remediation report'
            ),
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        parser.add_argument(
            'vulnerability_json',
            type=str,
            help='Path to the Trivy vulnerability JSON file.',
        )
        parser.add_argument(
            'jar_output_json',
            type=str,
            help='Path for the Java dependency-update output JSON file.',
        )
        parser.add_argument(
            'jar_report',
            type=str,
            help='Path for the Java plain-text remediation report.',
        )
        parser.add_argument(
            'os_output_json',
            type=str,
            help='Path for the OS package update output JSON file.',
        )
        parser.add_argument(
            'os_report',
            type=str,
            help='Path for the OS package plain-text remediation report.',
        )
        parser.add_argument(
            '--resolve-indirect',
            action='store_true',
            default=False,
            help=(
                'Attempt to resolve indirect (shaded) dependencies to a newer '
                'outer JAR version on Maven Central.  Requires network access.'
            ),
        )
        parser.add_argument(
            '--skip-prefixes',
            type=str,
            nargs='+',
            default=[],
            metavar='PREFIX',
            help=(
                'One or more filename prefixes for outer JARs that should be '
                'excluded from automatic resolution and written to the report '
                'instead (e.g. cassandra-data-migrator spark-).'
            ),
        )
        parser.add_argument(
            '--resolve-direct',
            action='store_true',
            default=False,
            help=(
                'Verify that each Trivy-recommended fixed version exists on Maven '
                'Central.  If it does not, query OSV.dev to find the highest '
                'published version with zero known vulnerabilities.  Packages with '
                'no safe version are written to Section E of the report.  Requires '
                'network access.'
            ),
        )
        parser.add_argument(
            '--resolver-timeout',
            type=int,
            default=20,
            metavar='SECONDS',
            help='Network timeout in seconds for Maven/OSV API calls (default: 20).',
        )
        return parser.parse_args()

    @staticmethod
    def main_cli() -> typing.Literal[0, 1]:
        parsed_args = ParseVulnerabilities._parse_args()

        try:
            print('--- Java vulnerabilities ---')
            java_parser = JarVulnerabilityParser(parsed_args.vulnerability_json)
            java_parser.run(
                output_json_path=parsed_args.jar_output_json,
                report_path=parsed_args.jar_report,
                resolve_direct=parsed_args.resolve_direct,
                resolve_indirect=parsed_args.resolve_indirect,
                skip_prefixes=parsed_args.skip_prefixes,
                resolver_timeout=parsed_args.resolver_timeout,
            )

            print('\n--- OS package vulnerabilities ---')
            os_parser = OsVulnerabilityParser(parsed_args.vulnerability_json)
            os_parser.run(
                output_json_path=parsed_args.os_output_json,
                report_path=parsed_args.os_report,
            )
        except Exception as e:
            print(f'Error: {e}', file=sys.stderr)
            return 1

        return 0


if __name__ == '__main__':
    sys.exit(ParseVulnerabilities.main_cli())
