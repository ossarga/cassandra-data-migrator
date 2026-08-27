#!/usr/bin/env python3
"""
update-os-packages.py

Reads an OS package update JSON file (produced by parse-vulnerabilities.py)
and generates a shell script that upgrades those packages using the target
container's package manager.

The generated script is intended to be COPY-ed into the final image stage of
the Dockerfile and executed there via a RUN step — it must not be run by this
script directly, because the package manager lives in the target container, not
in the Python build stage.

Supported package managers
---------------------------
  apk      Alpine / Chainguard  (apk add --no-cache [name=version ...])
  apt-get  Debian / Ubuntu      (apt-get install --no-install-recommends -y ...)
  dnf      Fedora / RHEL 8+     (dnf install -y ...)
  yum      RHEL / CentOS 7      (yum install -y ...)

Version pinning (default: on)
------------------------------
By default the generated script pins each package to the exact version listed
in the JSON (e.g. libcrypto3=3.5.8-r0 for apk).  This produces reproducible
builds but will fail if that exact version has since been removed from the
repository.

Pass --no-pin-versions to generate unpinned install commands (e.g.
`apk add --no-cache libcrypto3`), which always resolves to the latest
available version.

Input JSON schema
-----------------
[
  { "name": "libcrypto3", "versions": { "old": "3.5.7-r0", "new": "3.5.8-r0" } },
  ...
]
"""

import argparse
import json
import os
import sys
import typing
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

class OsUpdateEntry(typing.TypedDict):
    name: str
    versions: dict  # {"old": str, "new": str}


# ---------------------------------------------------------------------------
# Package manager handlers
# ---------------------------------------------------------------------------

class PackageManagerHandler:
    """Base class for package manager shell-script generators.

    Each subclass knows the exact shell syntax for its package manager:
    the preamble (e.g. repo refresh), the install command, and how to
    express a pinned vs. unpinned package argument.
    """

    #: Human-readable name shown in the generated script header comment.
    display_name: str = ''

    def preamble(self) -> list[str]:
        """Return shell lines that must run before any installs (e.g. repo sync).

        Returns an empty list when no preamble is needed.
        """
        return []

    def install_command(self) -> str:
        """Return the base install command (without package arguments)."""
        raise NotImplementedError

    def pinned_arg(self, name: str, version: str) -> str:
        """Return the package argument string when version pinning is active."""
        raise NotImplementedError

    def unpinned_arg(self, name: str) -> str:
        """Return the package argument string when version pinning is disabled."""
        return name


class ApkHandler(PackageManagerHandler):
    """Alpine Package Keeper — used by Alpine Linux and Chainguard images."""

    display_name = 'apk (Alpine / Chainguard)'

    def install_command(self) -> str:
        return 'apk add --no-cache'

    def pinned_arg(self, name: str, version: str) -> str:
        return f'{name}={version}'


class AptGetHandler(PackageManagerHandler):
    """apt-get — used by Debian and Ubuntu images."""

    display_name = 'apt-get (Debian / Ubuntu)'

    def preamble(self) -> list[str]:
        return ['apt-get update']

    def install_command(self) -> str:
        return 'apt-get install --no-install-recommends -y'

    def pinned_arg(self, name: str, version: str) -> str:
        # apt-get pin syntax: name=version
        return f'{name}={version}'


class DnfHandler(PackageManagerHandler):
    """dnf — used by Fedora and RHEL 8+ images."""

    display_name = 'dnf (Fedora / RHEL 8+)'

    def install_command(self) -> str:
        return 'dnf install -y'

    def pinned_arg(self, name: str, version: str) -> str:
        # dnf/rpm pin syntax: name-version (no epoch/arch suffix here)
        return f'{name}-{version}'


class YumHandler(PackageManagerHandler):
    """yum — used by RHEL / CentOS 7 images."""

    display_name = 'yum (RHEL / CentOS 7)'

    def install_command(self) -> str:
        return 'yum install -y'

    def pinned_arg(self, name: str, version: str) -> str:
        return f'{name}-{version}'


# Registry mapping the CLI --package-manager value to the handler class.
_HANDLERS: dict[str, type[PackageManagerHandler]] = {
    'apk':     ApkHandler,
    'apt-get': AptGetHandler,
    'dnf':     DnfHandler,
    'yum':     YumHandler,
}


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------

class OsPackageUpdater:
    """Reads an OS update JSON and writes a shell script for the given package manager."""

    def __init__(self, update_json_path: str) -> None:
        self._update_json_path = update_json_path
        self._packages: list[OsUpdateEntry] = []

    # ------------------------------------------------------------------
    # Loading and validation
    # ------------------------------------------------------------------

    def _load(self) -> None:
        with open(self._update_json_path, 'r') as fh:
            raw = json.load(fh)

        if not isinstance(raw, list):
            raise ValueError(
                f'{self._update_json_path} must contain a JSON array at the top level.'
            )

        validated: list[OsUpdateEntry] = []
        for i, entry in enumerate(raw):
            name = entry.get('name', '').strip()
            if not name:
                raise ValueError(f'Entry {i}: missing or empty "name" field.')

            versions = entry.get('versions')
            if not isinstance(versions, dict):
                raise ValueError(f'Entry {i} ({name!r}): missing "versions" object.')

            new_version = versions.get('new', '').strip()
            if not new_version:
                raise ValueError(
                    f'Entry {i} ({name!r}): missing or empty "versions.new" field.'
                )

            validated.append(OsUpdateEntry(name=name, versions=versions))

        self._packages = validated

    # ------------------------------------------------------------------
    # Script generation
    # ------------------------------------------------------------------

    def _build_script(
        self,
        handler: PackageManagerHandler,
        pin_versions: bool,
    ) -> str:
        timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        source = os.path.basename(self._update_json_path)

        lines: list[str] = [
            '#!/bin/sh',
            '# ----------------------------------------------------------------------',
            '# OS package security update script',
            f'# Generated : {timestamp}',
            f'# Source    : {source}',
            f'# Manager   : {handler.display_name}',
            f'# Pinned    : {"yes" if pin_versions else "no"}',
            '# ----------------------------------------------------------------------',
            'set -eu',
            '',
        ]

        # Preamble (e.g. apt-get update)
        for preamble_line in handler.preamble():
            lines.append(preamble_line)
        if handler.preamble():
            lines.append('')

        # Build the package argument list
        pkg_args: list[str] = []
        for entry in self._packages:
            name = entry['name']
            new_version = entry['versions']['new']
            if pin_versions:
                pkg_args.append(handler.pinned_arg(name, new_version))
            else:
                pkg_args.append(handler.unpinned_arg(name))

        # Emit as a single install command with one package per line for
        # readability, using shell line-continuation backslashes.
        install_cmd = handler.install_command()
        if len(pkg_args) == 1:
            lines.append(f'{install_cmd} {pkg_args[0]}')
        else:
            lines.append(f'{install_cmd} \\')
            for arg in pkg_args[:-1]:
                lines.append(f'  {arg} \\')
            lines.append(f'  {pkg_args[-1]}')

        lines.append('')
        return '\n'.join(lines)

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(
        self,
        output_sh_path: str,
        package_manager: str,
        pin_versions: bool,
    ) -> None:
        self._load()

        handler_class = _HANDLERS.get(package_manager)
        if handler_class is None:
            raise ValueError(
                f'Unknown package manager {package_manager!r}. '
                f'Supported: {", ".join(_HANDLERS)}.'
            )
        handler = handler_class()

        if not self._packages:
            print('No OS packages to update — output script will not be written.')
            return

        script = self._build_script(handler, pin_versions)

        with open(output_sh_path, 'w') as fh:
            fh.write(script)

        # Ensure the generated script is executable
        os.chmod(output_sh_path, 0o755)

        print(f'OS package update script written to: {output_sh_path}')
        print(f'  Package manager : {handler.display_name}')
        print(f'  Version pinning : {"on" if pin_versions else "off"}')
        print(f'  Packages        : {len(self._packages)}')
        for entry in self._packages:
            name = entry['name']
            old = entry['versions'].get('old', '?')
            new = entry['versions']['new']
            pin_str = f' (pinned to {new})' if pin_versions else f' (latest, was {old})'
            print(f'    {name}: {old} -> {new}{pin_str}')


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

class UpdateOsPackages:
    @staticmethod
    def _parse_args() -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description=(
                'Generate a shell script that upgrades OS packages listed in an\n'
                'OS package update JSON file (produced by parse-vulnerabilities.py).'
            ),
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        parser.add_argument(
            'os_update_json',
            type=str,
            help='Path to the OS package update JSON file.',
        )
        parser.add_argument(
            'output_sh',
            type=str,
            help='Path for the generated shell script.',
        )
        parser.add_argument(
            '--package-manager',
            type=str,
            default='apk',
            choices=list(_HANDLERS.keys()),
            metavar='MANAGER',
            help=(
                f'Package manager to generate commands for. '
                f'Choices: {", ".join(_HANDLERS)}. Default: apk.'
            ),
        )
        parser.add_argument(
            '--no-pin-versions',
            action='store_true',
            default=False,
            help=(
                'Generate unpinned install commands (e.g. `apk add libcrypto3`) '
                'instead of version-pinned ones (e.g. `apk add libcrypto3=3.5.8-r0`). '
                'Pinning is on by default for reproducible builds.'
            ),
        )
        return parser.parse_args()

    @staticmethod
    def main_cli() -> typing.Literal[0, 1]:
        parsed_args = UpdateOsPackages._parse_args()

        try:
            updater = OsPackageUpdater(parsed_args.os_update_json)
            updater.run(
                output_sh_path=parsed_args.output_sh,
                package_manager=parsed_args.package_manager,
                pin_versions=not parsed_args.no_pin_versions,
            )
        except Exception as e:
            print(f'Error: {e}', file=sys.stderr)
            return 1

        return 0


if __name__ == '__main__':
    sys.exit(UpdateOsPackages.main_cli())
