#!/usr/bin/env python3
"""
Unit tests for build-tools/update-jar-dependencies.py

Tests cover:
  - DependencyLib._build_filenames        (filename / lib_name derivation)
  - DependencyLib._check_downloaded_file  (JAR validation)
  - DependencyLib._download_new_lib       (retry-with-backoff logic)
  - DependencyLib.update                  (file-swap logic)
  - UpdateDependencies.main_cli           (JSON parsing + regex matching)
"""

import io
import json
import os
import shutil
import sys
import tempfile
import unittest
import urllib.error
import zipfile
from unittest.mock import MagicMock, call, patch

# Load the hyphen-named module via importlib (hyphens are not valid in Python
# identifiers so a direct `import` statement cannot be used)
import importlib.util as _ilu

_spec = _ilu.spec_from_file_location(
    'update_jar_dependencies',
    os.path.join(os.path.dirname(__file__), '..', 'update-jar-dependencies.py'),
)
_mod = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
DependencyLib = _mod.DependencyLib
UpdateDependencies = _mod.UpdateDependencies


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_valid_jar(path: str) -> None:
    """Write a minimal valid JAR (ZIP + META-INF/MANIFEST.MF) to *path*."""
    with zipfile.ZipFile(path, 'w') as zf:
        zf.writestr('META-INF/MANIFEST.MF', 'Manifest-Version: 1.0\n')


def _make_dep_lib(
    filename='lz4-java-1.11.0.jar',
    group='at.yawk.lz4',
    old_version='1.11.0',
    new_version='1.11.1',
    retries=3,
    retry_delay=0.0,   # zero delay so tests finish instantly
) -> DependencyLib:
    return DependencyLib(
        filename, group, old_version, new_version,
        retries=retries, retry_delay=retry_delay,
    )


# ---------------------------------------------------------------------------
# _build_filenames
# ---------------------------------------------------------------------------

class TestBuildFilenames(unittest.TestCase):

    def test_simple_version_bump(self):
        lib = _make_dep_lib('lz4-java-1.11.0.jar', old_version='1.11.0', new_version='1.11.1')
        self.assertEqual(lib.new_filename, 'lz4-java-1.11.1.jar')
        self.assertEqual(lib.lib_name, 'lz4-java')

    def test_final_qualifier(self):
        lib = _make_dep_lib(
            'netty-handler-4.2.7.Final.jar',
            group='io.netty',
            old_version='4.2.7.Final',
            new_version='4.2.15.Final',
        )
        self.assertEqual(lib.new_filename, 'netty-handler-4.2.15.Final.jar')
        self.assertEqual(lib.lib_name, 'netty-handler')

    def test_arch_classifier_preserved(self):
        lib = _make_dep_lib(
            'netty-transport-native-epoll-4.2.7.Final-linux-x86_64.jar',
            group='io.netty',
            old_version='4.2.7.Final',
            new_version='4.2.15.Final',
        )
        self.assertEqual(
            lib.new_filename,
            'netty-transport-native-epoll-4.2.15.Final-linux-x86_64.jar',
        )
        self.assertEqual(lib.lib_name, 'netty-transport-native-epoll')

    def test_multi_component_name(self):
        lib = _make_dep_lib(
            'netty-codec-http2-4.2.13.Final.jar',
            group='io.netty',
            old_version='4.2.13.Final',
            new_version='4.2.16.Final',
        )
        self.assertEqual(lib.new_filename, 'netty-codec-http2-4.2.16.Final.jar')
        self.assertEqual(lib.lib_name, 'netty-codec-http2')


# ---------------------------------------------------------------------------
# _check_downloaded_file
# ---------------------------------------------------------------------------

class TestCheckDownloadedFile(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_valid_jar_passes(self):
        path = os.path.join(self.tmp, 'valid.jar')
        _make_valid_jar(path)
        # Should not raise
        DependencyLib._check_downloaded_file(path)

    def test_missing_file_raises(self):
        with self.assertRaises(FileExistsError):
            DependencyLib._check_downloaded_file('/nonexistent/path/file.jar')

    def test_empty_file_raises(self):
        path = os.path.join(self.tmp, 'empty.jar')
        open(path, 'w').close()
        with self.assertRaises(ValueError):
            DependencyLib._check_downloaded_file(path)

    def test_bad_zip_raises(self):
        path = os.path.join(self.tmp, 'notazip.jar')
        with open(path, 'wb') as fh:
            fh.write(b'this is not a zip file at all')
        with self.assertRaises(zipfile.BadZipFile):
            DependencyLib._check_downloaded_file(path)

    def test_zip_without_manifest_raises(self):
        path = os.path.join(self.tmp, 'nomanifest.jar')
        with zipfile.ZipFile(path, 'w') as zf:
            zf.writestr('com/example/Foo.class', b'\xca\xfe\xba\xbe')
        with self.assertRaises(ValueError):
            DependencyLib._check_downloaded_file(path)


# ---------------------------------------------------------------------------
# _download_new_lib  — retry-with-backoff
# ---------------------------------------------------------------------------

class TestDownloadRetry(unittest.TestCase):
    """Tests for the retry logic in _download_new_lib."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def _patch_download(self, lib: DependencyLib, side_effects):
        """Patch urlretrieve and _check_downloaded_file together.

        side_effects is a list of values for urlretrieve: use None for success
        and an Exception subclass instance to simulate a failure.
        """
        call_iter = iter(side_effects)

        def fake_urlretrieve(url, dest):
            effect = next(call_iter)
            if isinstance(effect, Exception):
                raise effect

        return patch('urllib.request.urlretrieve', side_effect=fake_urlretrieve)

    def test_success_on_first_attempt(self):
        lib = _make_dep_lib(retries=3, retry_delay=0.0)
        jar_path = os.path.join(tempfile.gettempdir(), lib.new_filename)
        _make_valid_jar(jar_path)
        try:
            with patch('urllib.request.urlretrieve'):
                lib._download_new_lib()
            self.assertEqual(lib._new_file_temp_path, jar_path)
        finally:
            if os.path.exists(jar_path):
                os.remove(jar_path)

    def test_retries_on_transient_error_then_succeeds(self):
        lib = _make_dep_lib(retries=3, retry_delay=0.0)
        jar_path = os.path.join(tempfile.gettempdir(), lib.new_filename)
        _make_valid_jar(jar_path)

        attempts = []

        def fake_urlretrieve(url, dest):
            attempts.append(url)
            if len(attempts) < 2:
                raise ConnectionResetError('transient network error')
            # second attempt succeeds — file already exists from setUp

        try:
            with patch('urllib.request.urlretrieve', side_effect=fake_urlretrieve), \
                 patch('time.sleep') as mock_sleep:
                lib._download_new_lib()

            self.assertEqual(len(attempts), 2)
            # Backoff was called once (between attempt 1 and 2)
            mock_sleep.assert_called_once_with(0.0)   # retry_delay=0.0 × 2^0
        finally:
            if os.path.exists(jar_path):
                os.remove(jar_path)

    def test_exhausts_retries_and_raises_last_exception(self):
        lib = _make_dep_lib(retries=3, retry_delay=0.0)

        error = ConnectionResetError('always fails')

        with patch('urllib.request.urlretrieve', side_effect=error), \
             patch('time.sleep'):
            with self.assertRaises(ConnectionResetError):
                lib._download_new_lib()

    def test_http_error_not_retried(self):
        """HTTP errors (e.g. 404) should be raised immediately, not retried."""
        lib = _make_dep_lib(retries=5, retry_delay=0.0)

        http_err = urllib.error.HTTPError(
            url='http://example.com', code=404,
            msg='Not Found', hdrs=None, fp=None,
        )
        call_count = []

        def fake_urlretrieve(url, dest):
            call_count.append(1)
            raise http_err

        with patch('urllib.request.urlretrieve', side_effect=fake_urlretrieve), \
             patch('time.sleep') as mock_sleep:
            with self.assertRaises(urllib.error.HTTPError):
                lib._download_new_lib()

        # Must not have retried
        self.assertEqual(sum(call_count), 1)
        mock_sleep.assert_not_called()

    def test_backoff_doubles_each_attempt(self):
        """Verify the delay sequence: delay, delay×2, delay×4 ..."""
        lib = _make_dep_lib(retries=4, retry_delay=5.0)

        with patch('urllib.request.urlretrieve', side_effect=OSError('fail')), \
             patch('time.sleep') as mock_sleep:
            with self.assertRaises(OSError):
                lib._download_new_lib()

        # 4 retries → 3 sleep calls (no sleep after the last attempt)
        expected_delays = [5.0, 10.0, 20.0]
        actual_delays = [c.args[0] for c in mock_sleep.call_args_list]
        self.assertEqual(actual_delays, expected_delays)


# ---------------------------------------------------------------------------
# DependencyLib.update  — file-swap logic
# ---------------------------------------------------------------------------

class TestUpdate(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def _setup_lib_with_downloaded_file(self) -> tuple[DependencyLib, str]:
        """Return a DependencyLib whose _new_file_temp_path is a valid JAR.

        The temp download directory and the dep directory are kept separate so
        that shutil.copy2 never sees src == dst (which would raise SameFileError).
        """
        lib = _make_dep_lib()

        # Simulate a downloaded temp file in a separate staging directory
        staging_dir = tempfile.mkdtemp()
        jar_path = os.path.join(staging_dir, lib.new_filename)
        _make_valid_jar(jar_path)
        lib._new_file_temp_path = jar_path
        # Register staging dir for cleanup via the file bin mechanism
        lib._staging_dir = staging_dir

        # Simulate the old JAR already being present in the dep directory
        old_jar = os.path.join(self.tmp, lib.old_filename)
        _make_valid_jar(old_jar)

        return lib, jar_path

    def tearDown(self):
        super().tearDown()
        # Clean up any staging dirs created by _setup_lib_with_downloaded_file
        for attr in ('_staging_dir',):
            pass  # staging files are cleaned up via the regular shutil.rmtree on self.tmp

    def test_successful_update_creates_new_file_and_queues_old_for_deletion(self):
        lib, staging_jar = self._setup_lib_with_downloaded_file()
        lib.update(self.tmp)

        new_path = os.path.join(self.tmp, lib.new_filename)
        self.assertTrue(os.path.isfile(new_path))
        # Old file path is queued in the bin (not deleted yet — __exit__ does that)
        old_path = os.path.join(self.tmp, lib.old_filename)
        self.assertIn(old_path, lib._file_bin)

        # Cleanup staging dir
        shutil.rmtree(os.path.dirname(staging_jar), ignore_errors=True)

    def test_update_does_nothing_when_temp_path_not_set(self):
        lib = _make_dep_lib()
        # _new_file_temp_path is '' by default — update should be a no-op
        lib.update(self.tmp)
        self.assertFalse(os.path.isfile(os.path.join(self.tmp, lib.new_filename)))


# ---------------------------------------------------------------------------
# UpdateDependencies.main_cli  — JSON + regex matching
# ---------------------------------------------------------------------------

class TestMainCli(unittest.TestCase):
    """Integration-style tests for main_cli that mock network calls."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def _write_dep_json(self, entries: list) -> str:
        path = os.path.join(self.tmp, 'deps.json')
        with open(path, 'w') as fh:
            json.dump(entries, fh)
        return path

    def _run_cli(self, dep_json_path: str, dep_dir: str, extra_args=None) -> int:
        argv = ['update-jar-dependencies.py', dep_json_path, dep_dir]
        if extra_args:
            argv.extend(extra_args)
        with patch('sys.argv', argv):
            return UpdateDependencies.main_cli()

    def test_single_jar_updated_successfully(self):
        """A matching JAR in the dep dir is replaced with the new version."""
        old_jar = 'lz4-java-1.11.0.jar'
        new_jar = 'lz4-java-1.11.1.jar'

        # Create the old JAR in the dep dir
        _make_valid_jar(os.path.join(self.tmp, old_jar))

        dep_json = self._write_dep_json([{
            'name': 'lz4-java',
            'group': 'at.yawk.lz4',
            'versions': {'old': '1.11.0', 'new': '1.11.1'},
        }])

        new_jar_src = os.path.join(tempfile.gettempdir(), new_jar)
        _make_valid_jar(new_jar_src)

        try:
            with patch('urllib.request.urlretrieve'):
                result = self._run_cli(dep_json, self.tmp)

            self.assertEqual(result, 0)
            self.assertTrue(os.path.isfile(os.path.join(self.tmp, new_jar)))
            # Old JAR is cleaned up by the context manager __exit__
            self.assertFalse(os.path.isfile(os.path.join(self.tmp, old_jar)))
        finally:
            if os.path.exists(new_jar_src):
                os.remove(new_jar_src)

    def test_no_matching_jar_is_a_no_op(self):
        """If no file in the dep dir matches, the run succeeds with no changes."""
        _make_valid_jar(os.path.join(self.tmp, 'unrelated-1.0.0.jar'))

        dep_json = self._write_dep_json([{
            'name': 'lz4-java',
            'group': 'at.yawk.lz4',
            'versions': {'old': '1.11.0', 'new': '1.11.1'},
        }])

        with patch('urllib.request.urlretrieve'):
            result = self._run_cli(dep_json, self.tmp)

        self.assertEqual(result, 0)

    def test_http_error_returns_exit_code_1(self):
        """A 404 from Maven Central causes main_cli to return 1."""
        _make_valid_jar(os.path.join(self.tmp, 'lz4-java-1.11.0.jar'))

        dep_json = self._write_dep_json([{
            'name': 'lz4-java',
            'group': 'at.yawk.lz4',
            'versions': {'old': '1.11.0', 'new': '9.99.99'},
        }])

        http_err = urllib.error.HTTPError(
            url='http://example.com', code=404,
            msg='Not Found', hdrs=None, fp=None,
        )

        with patch('urllib.request.urlretrieve', side_effect=http_err):
            result = self._run_cli(dep_json, self.tmp)

        self.assertEqual(result, 1)

    def test_arch_classifier_jar_matched_by_regex(self):
        """Jars with an arch classifier like -linux-x86_64 are matched correctly."""
        old_jar = 'netty-transport-native-epoll-4.2.13.Final-linux-x86_64.jar'
        new_jar = 'netty-transport-native-epoll-4.2.15.Final-linux-x86_64.jar'

        _make_valid_jar(os.path.join(self.tmp, old_jar))

        dep_json = self._write_dep_json([{
            'name': 'netty-transport-native-epoll',
            'group': 'io.netty',
            'versions': {'old': '4.2.13.Final', 'new': '4.2.15.Final'},
        }])

        new_jar_src = os.path.join(tempfile.gettempdir(), new_jar)
        _make_valid_jar(new_jar_src)

        try:
            with patch('urllib.request.urlretrieve'):
                result = self._run_cli(dep_json, self.tmp)

            self.assertEqual(result, 0)
            self.assertTrue(os.path.isfile(os.path.join(self.tmp, new_jar)))
        finally:
            if os.path.exists(new_jar_src):
                os.remove(new_jar_src)

    def test_empty_dep_list_is_a_no_op(self):
        dep_json = self._write_dep_json([])
        result = self._run_cli(dep_json, self.tmp)
        self.assertEqual(result, 0)

    def test_custom_retries_and_delay_are_passed_through(self):
        """--retries and --retry-delay reach DependencyLib correctly."""
        _make_valid_jar(os.path.join(self.tmp, 'lz4-java-1.11.0.jar'))

        dep_json = self._write_dep_json([{
            'name': 'lz4-java',
            'group': 'at.yawk.lz4',
            'versions': {'old': '1.11.0', 'new': '1.11.1'},
        }])

        new_jar_src = os.path.join(tempfile.gettempdir(), 'lz4-java-1.11.1.jar')
        _make_valid_jar(new_jar_src)

        captured = {}

        original_init = DependencyLib.__init__

        def capturing_init(self_inner, *args, **kwargs):
            captured['retries'] = kwargs.get('retries')
            captured['retry_delay'] = kwargs.get('retry_delay')
            original_init(self_inner, *args, **kwargs)

        try:
            with patch.object(DependencyLib, '__init__', capturing_init), \
                 patch('urllib.request.urlretrieve'):
                self._run_cli(dep_json, self.tmp, extra_args=['--retries', '7', '--retry-delay', '2.5'])

            self.assertEqual(captured['retries'], 7)
            self.assertAlmostEqual(captured['retry_delay'], 2.5)
        finally:
            if os.path.exists(new_jar_src):
                os.remove(new_jar_src)


# ---------------------------------------------------------------------------
# Module-level import guard
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    unittest.main()
