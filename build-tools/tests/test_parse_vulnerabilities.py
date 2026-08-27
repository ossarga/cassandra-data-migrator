#!/usr/bin/env python3
"""
Unit tests for build-tools/parse-vulnerabilities.py

Tests cover:
  - _version_key / _latest_fixed_version   (version sorting helpers)
  - JarVulnerabilityParser._split_pkg_name (group:artifact parsing)
  - JarVulnerabilityParser._jar_filename   (PkgPath → filename)
  - JarVulnerabilityParser._classify       (direct vs indirect, fixed vs not)
  - OsVulnerabilityParser._classify        (OS package classification)
  - Full run() against a minimal synthetic Trivy report
"""

import importlib.util as _ilu
import json
import os
import sys
import tempfile
import shutil
import unittest
from unittest.mock import patch

# ---------------------------------------------------------------------------
# Module import (hyphen in filename requires importlib)
# ---------------------------------------------------------------------------

_spec = _ilu.spec_from_file_location(
    'parse_vulnerabilities',
    os.path.join(os.path.dirname(__file__), '..', 'parse-vulnerabilities.py'),
)
_mod = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

_version_key = _mod._version_key
_latest_fixed_version = _mod._latest_fixed_version
JarVulnerabilityParser = _mod.JarVulnerabilityParser
OsVulnerabilityParser = _mod.OsVulnerabilityParser


# ---------------------------------------------------------------------------
# Minimal synthetic Trivy report builder
# ---------------------------------------------------------------------------

def _make_report(java_vulns: list, os_vulns: list | None = None) -> dict:
    """Build the minimal Trivy JSON structure the parsers expect."""
    results = [
        {
            'Target': 'Java',
            'Class': 'lang-pkgs',
            'Type': 'jar',
            'Vulnerabilities': java_vulns,
        },
        {
            'Target': 'alpine (alpine 3.24.1)',
            'Class': 'os-pkgs',
            'Type': 'alpine',
            'Vulnerabilities': os_vulns or [],
        },
    ]
    return {
        'SchemaVersion': 2,
        'ArtifactName': 'test-image:latest',
        'Results': results,
    }


def _java_vuln(
    pkg_name: str,
    pkg_path: str,
    installed: str,
    fixed: str,
    status: str = 'fixed',
    vuln_id: str = 'CVE-2025-0001',
    severity: str = 'HIGH',
) -> dict:
    return {
        'VulnerabilityID': vuln_id,
        'PkgName': pkg_name,
        'PkgPath': pkg_path,
        'InstalledVersion': installed,
        'FixedVersion': fixed,
        'Status': status,
        'Severity': severity,
        'Title': 'Test vulnerability',
        'PrimaryURL': 'https://example.com/cve',
    }


def _os_vuln(
    pkg_name: str,
    installed: str,
    fixed: str,
    status: str = 'fixed',
    vuln_id: str = 'CVE-2025-9999',
    severity: str = 'MEDIUM',
) -> dict:
    return {
        'VulnerabilityID': vuln_id,
        'PkgName': pkg_name,
        'InstalledVersion': installed,
        'FixedVersion': fixed,
        'Status': status,
        'Severity': severity,
        'Title': 'OS test vulnerability',
        'PrimaryURL': 'https://example.com/os-cve',
    }


# ---------------------------------------------------------------------------
# _version_key
# ---------------------------------------------------------------------------

class TestVersionKey(unittest.TestCase):

    def test_numeric_comparison(self):
        self.assertLess(_version_key('1.2.3'), _version_key('1.2.10'))

    def test_final_qualifier_sorts_after_numeric(self):
        # '4.2.7.Final' should sort higher than '4.2.7'
        self.assertGreater(_version_key('4.2.7.Final'), _version_key('4.2.7'))

    def test_equal_versions(self):
        self.assertEqual(_version_key('2.21.4'), _version_key('2.21.4'))

    def test_major_version_dominates(self):
        self.assertLess(_version_key('1.99.99'), _version_key('2.0.0'))


# ---------------------------------------------------------------------------
# _latest_fixed_version
# ---------------------------------------------------------------------------

class TestLatestFixedVersion(unittest.TestCase):

    def test_single_version(self):
        self.assertEqual(_latest_fixed_version('2.21.4'), '2.21.4')

    def test_comma_separated_picks_highest(self):
        # Trivy lists are unordered — must sort numerically, not by position
        self.assertEqual(_latest_fixed_version('2.18.8, 2.21.4'), '2.21.4')

    def test_unordered_list(self):
        self.assertEqual(
            _latest_fixed_version('10.14.2.1, 10.16.1.2, 10.15.2.1'),
            '10.16.1.2',
        )

    def test_final_qualifier(self):
        self.assertEqual(
            _latest_fixed_version('4.2.15.Final, 4.1.135.Final'),
            '4.2.15.Final',
        )

    def test_empty_string(self):
        self.assertEqual(_latest_fixed_version(''), '')

    def test_whitespace_only_entries_ignored(self):
        # ' , , ' splits into [' ', ' ', ' '] — all strip to '' so the list of
        # non-empty parts is empty and the fallback returns the stripped input.
        # This is a degenerate input that never appears in real Trivy data;
        # the important invariant is that it does not raise.
        result = _latest_fixed_version(' , , ')
        self.assertIsInstance(result, str)


# ---------------------------------------------------------------------------
# JarVulnerabilityParser helpers
# ---------------------------------------------------------------------------

class TestJarParserHelpers(unittest.TestCase):

    def test_split_pkg_name_with_colon(self):
        g, a = JarVulnerabilityParser._split_pkg_name('at.yawk.lz4:lz4-java')
        self.assertEqual(g, 'at.yawk.lz4')
        self.assertEqual(a, 'lz4-java')

    def test_split_pkg_name_no_colon(self):
        g, a = JarVulnerabilityParser._split_pkg_name('standalone')
        self.assertEqual(g, '')
        self.assertEqual(a, 'standalone')

    def test_jar_filename_from_path(self):
        filename = JarVulnerabilityParser._jar_filename(
            'opt/spark/jars/lz4-java-1.11.0.jar'
        )
        self.assertEqual(filename, 'lz4-java-1.11.0.jar')

    def test_jar_filename_no_slash(self):
        filename = JarVulnerabilityParser._jar_filename('lz4-java-1.11.0.jar')
        self.assertEqual(filename, 'lz4-java-1.11.0.jar')


# ---------------------------------------------------------------------------
# JarVulnerabilityParser._classify
# ---------------------------------------------------------------------------

class TestJarClassify(unittest.TestCase):
    """Tests for the direct / indirect classification logic."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def _make_parser(self, java_vulns, os_vulns=None):
        report = _make_report(java_vulns, os_vulns)
        path = os.path.join(self.tmp, 'report.json')
        with open(path, 'w') as fh:
            json.dump(report, fh)
        parser = JarVulnerabilityParser(path)
        parser._load()
        return parser

    def test_direct_fixed_becomes_update_entry(self):
        """Artifact name present in JAR filename + status=fixed → update JSON."""
        vulns = [_java_vuln(
            pkg_name='at.yawk.lz4:lz4-java',
            pkg_path='opt/spark/jars/lz4-java-1.11.0.jar',
            installed='1.11.0',
            fixed='1.11.1',
        )]
        parser = self._make_parser(vulns)
        updates, not_fixed, indirect_res, indirect_skip, unresolvable = \
            parser._classify(skip_prefixes=[], resolve_direct=False, resolver_timeout=20)

        self.assertEqual(len(updates), 1)
        self.assertEqual(updates[0]['name'], 'lz4-java')
        self.assertEqual(updates[0]['group'], 'at.yawk.lz4')
        self.assertEqual(updates[0]['versions']['old'], '1.11.0')
        self.assertEqual(updates[0]['versions']['new'], '1.11.1')
        self.assertEqual(not_fixed, [])
        self.assertEqual(indirect_res, {})

    def test_direct_not_fixed_goes_to_section_a(self):
        """Artifact name in JAR filename + status!=fixed → Section A report."""
        vulns = [_java_vuln(
            pkg_name='commons-lang:commons-lang',
            pkg_path='opt/spark/jars/commons-lang-2.6.jar',
            installed='2.6',
            fixed='',
            status='affected',
        )]
        parser = self._make_parser(vulns)
        updates, not_fixed, indirect_res, indirect_skip, unresolvable = \
            parser._classify(skip_prefixes=[], resolve_direct=False, resolver_timeout=20)

        self.assertEqual(updates, [])
        self.assertEqual(len(not_fixed), 1)
        self.assertEqual(not_fixed[0]['pkg_name'], 'commons-lang:commons-lang')

    def test_indirect_goes_to_indirect_resolvable(self):
        """Artifact name absent from JAR filename → indirect bucket."""
        vulns = [_java_vuln(
            pkg_name='com.fasterxml.jackson.core:jackson-core',
            pkg_path='opt/spark/jars/hadoop-client-runtime-3.5.0.jar',
            installed='2.18.6',
            fixed='2.21.4',
        )]
        parser = self._make_parser(vulns)
        updates, not_fixed, indirect_res, indirect_skip, unresolvable = \
            parser._classify(skip_prefixes=[], resolve_direct=False, resolver_timeout=20)

        self.assertEqual(updates, [])
        self.assertIn('hadoop-client-runtime-3.5.0.jar', indirect_res)

    def test_indirect_skipped_by_prefix(self):
        """Outer JAR matching a --skip-prefixes entry → indirect_skip bucket."""
        vulns = [_java_vuln(
            pkg_name='io.netty:netty-handler',
            pkg_path='opt/cassandra-data-migrator/cassandra-data-migrator-6.0.1.jar',
            installed='4.2.7.Final',
            fixed='4.2.15.Final',
        )]
        parser = self._make_parser(vulns)
        updates, not_fixed, indirect_res, indirect_skip, unresolvable = \
            parser._classify(
                skip_prefixes=['cassandra-data-migrator'],
                resolve_direct=False,
                resolver_timeout=20,
            )

        self.assertEqual(updates, [])
        self.assertIn('cassandra-data-migrator-6.0.1.jar', indirect_skip)
        self.assertEqual(indirect_res, {})

    def test_deduplication_keeps_highest_fixed_version(self):
        """Multiple CVEs for the same (artifact, installed) keep the highest fix."""
        vulns = [
            _java_vuln(
                pkg_name='com.fasterxml.jackson.core:jackson-databind',
                pkg_path='opt/spark/jars/jackson-databind-2.21.2.jar',
                installed='2.21.2',
                fixed='2.21.4',
                vuln_id='CVE-2025-0001',
            ),
            _java_vuln(
                pkg_name='com.fasterxml.jackson.core:jackson-databind',
                pkg_path='opt/spark/jars/jackson-databind-2.21.2.jar',
                installed='2.21.2',
                fixed='2.22.1',   # higher — should win
                vuln_id='CVE-2025-0002',
            ),
        ]
        parser = self._make_parser(vulns)
        updates, _, _, _, _ = parser._classify(
            skip_prefixes=[], resolve_direct=False, resolver_timeout=20
        )

        self.assertEqual(len(updates), 1)
        self.assertEqual(updates[0]['versions']['new'], '2.22.1')

    def test_unordered_fixed_version_list_resolved_to_highest(self):
        """Comma-separated FixedVersion is sorted, not taken by last position."""
        vulns = [_java_vuln(
            pkg_name='org.apache.derby:derby',
            pkg_path='opt/spark/jars/derby-10.16.1.1.jar',
            installed='10.16.1.1',
            fixed='10.14.2.1, 10.16.1.2, 10.15.2.1',  # unsorted
        )]
        parser = self._make_parser(vulns)
        updates, _, _, _, _ = parser._classify(
            skip_prefixes=[], resolve_direct=False, resolver_timeout=20
        )

        self.assertEqual(updates[0]['versions']['new'], '10.16.1.2')


# ---------------------------------------------------------------------------
# OsVulnerabilityParser._classify
# ---------------------------------------------------------------------------

class TestOsClassify(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def _make_parser(self, os_vulns):
        report = _make_report([], os_vulns)
        path = os.path.join(self.tmp, 'report.json')
        with open(path, 'w') as fh:
            json.dump(report, fh)
        parser = OsVulnerabilityParser(path)
        parser._load()
        return parser

    def test_fixed_os_pkg_becomes_update_entry(self):
        parser = self._make_parser([
            _os_vuln('libssl3', '3.3.0-r2', '3.3.1-r0')
        ])
        updates, not_fixed = parser._classify()

        self.assertEqual(len(updates), 1)
        self.assertEqual(updates[0]['name'], 'libssl3')
        self.assertEqual(updates[0]['versions']['old'], '3.3.0-r2')
        self.assertEqual(updates[0]['versions']['new'], '3.3.1-r0')

    def test_not_fixed_os_pkg_goes_to_section_a(self):
        parser = self._make_parser([
            _os_vuln('busybox', '1.36.0-r0', '', status='affected')
        ])
        updates, not_fixed = parser._classify()

        self.assertEqual(updates, [])
        self.assertEqual(len(not_fixed), 1)
        self.assertEqual(not_fixed[0]['pkg_name'], 'busybox')

    def test_os_deduplication(self):
        """Multiple CVEs for the same (name, installed) produce one update entry."""
        parser = self._make_parser([
            _os_vuln('libssl3', '3.3.0-r2', '3.3.1-r0', vuln_id='CVE-A'),
            _os_vuln('libssl3', '3.3.0-r2', '3.3.2-r0', vuln_id='CVE-B'),
        ])
        updates, _ = parser._classify()
        self.assertEqual(len(updates), 1)


# ---------------------------------------------------------------------------
# Full run() integration — synthetic Trivy report
# ---------------------------------------------------------------------------

class TestFullRun(unittest.TestCase):
    """End-to-end: write a synthetic Trivy report, run both parsers, verify outputs."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def _paths(self):
        return (
            os.path.join(self.tmp, 'report.json'),
            os.path.join(self.tmp, 'java-updates.json'),
            os.path.join(self.tmp, 'java-report.txt'),
            os.path.join(self.tmp, 'os-updates.json'),
            os.path.join(self.tmp, 'os-report.txt'),
        )

    def test_run_produces_correct_output_files(self):
        report_path, jar_json, jar_report, os_json, os_report = self._paths()

        report = _make_report(
            java_vulns=[
                # Direct + fixed → should appear in jar output JSON
                _java_vuln(
                    'at.yawk.lz4:lz4-java',
                    'opt/spark/jars/lz4-java-1.11.0.jar',
                    '1.11.0', '1.11.1',
                ),
                # Indirect → should appear in report Section D (not resolved)
                _java_vuln(
                    'com.fasterxml.jackson.core:jackson-core',
                    'opt/spark/jars/hadoop-client-runtime-3.5.0.jar',
                    '2.18.6', '2.21.4',
                ),
                # Direct + not fixed → should appear in report Section A
                _java_vuln(
                    'commons-lang:commons-lang',
                    'opt/spark/jars/commons-lang-2.6.jar',
                    '2.6', '',
                    status='affected',
                ),
            ],
            os_vulns=[
                _os_vuln('libssl3', '3.3.0-r2', '3.3.1-r0'),
                _os_vuln('musl', '1.2.4-r2', '', status='affected'),
            ],
        )

        with open(report_path, 'w') as fh:
            json.dump(report, fh)

        java_parser = JarVulnerabilityParser(report_path)
        java_parser.run(
            output_json_path=jar_json,
            report_path=jar_report,
            resolve_direct=False,
            resolve_indirect=False,
            skip_prefixes=[],
            resolver_timeout=20,
        )

        os_parser = OsVulnerabilityParser(report_path)
        os_parser.run(output_json_path=os_json, report_path=os_report)

        # --- Java output JSON ---
        with open(jar_json) as fh:
            jar_updates = json.load(fh)

        self.assertEqual(len(jar_updates), 1)
        self.assertEqual(jar_updates[0]['name'], 'lz4-java')
        self.assertEqual(jar_updates[0]['versions']['new'], '1.11.1')

        # --- Java report ---
        with open(jar_report) as fh:
            jar_report_text = fh.read()

        self.assertIn('SECTION A', jar_report_text)
        self.assertIn('commons-lang:commons-lang', jar_report_text)
        self.assertIn('SECTION D', jar_report_text)
        self.assertIn('hadoop-client-runtime-3.5.0.jar', jar_report_text)

        # --- OS output JSON ---
        with open(os_json) as fh:
            os_updates = json.load(fh)

        self.assertEqual(len(os_updates), 1)
        self.assertEqual(os_updates[0]['name'], 'libssl3')

        # --- OS report ---
        with open(os_report) as fh:
            os_report_text = fh.read()

        self.assertIn('SECTION A', os_report_text)
        self.assertIn('musl', os_report_text)


if __name__ == '__main__':
    unittest.main()
