#!/usr/bin/env python3

import argparse
import json
import os
import re
import shutil
import sys
import tempfile
import typing
import urllib.request
import urllib.error
import zipfile


class DependencyLib:
    def __init__(self, filename: str, group_path: str, old_version: str, new_version: str) -> None:
        self._old_version = old_version
        self._new_version = new_version

        self._group_path = group_path
        self.old_filename = filename
        self.new_filename = ''

        self.lib_name = ''

        self._new_file_temp_path = ''

        self._build_filenames()
        
        self._file_bin = []


    def __enter__(self) -> typing.Any:
        self._download_new_lib()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self._empty_file_bin()
        return None

    def _build_filenames(self) -> None:
        self.new_filename = self.old_filename.replace(self._old_version, self._new_version)

        version_index = self.new_filename.find(self._new_version)
        version_index -= 1
        self.lib_name = self.new_filename[0:version_index]

    @staticmethod
    def _check_downloaded_file(file_path) -> None:
        if os.path.isfile(file_path):
            if os.path.getsize(file_path) > 0:
                if zipfile.is_zipfile(file_path):
                    try:
                        with zipfile.ZipFile(file_path, 'r') as archive:
                            namelist = archive.namelist()
                            if "META-INF/MANIFEST.MF" in namelist:
                                return
                            else:
                                raise ValueError(f'Error: Invalid JAR, {file_path} is missing a manifest file')
                    except Exception as e:
                        raise e
                else:
                    raise zipfile.BadZipFile(f'Error: Invalid JAR, {file_path} is a bad ZIP file')
            else:
                raise ValueError(f'Error: Download failed, {file_path} is 0 bytes')
        else:
            raise FileExistsError(f'Error: Download failed, unable to locate {file_path}')


    def _download_new_lib(self) -> None:
        new_file_temp_path = os.path.join(tempfile.gettempdir(), self.new_filename)
        maven_url = 'https://repo1.maven.org/maven2/' \
            + \
            f'{self._group_path}/{self.lib_name}/{self._new_version}/{self.new_filename}'

        try:
            urllib.request.urlretrieve(maven_url, new_file_temp_path)
            DependencyLib._check_downloaded_file(new_file_temp_path)
            print(f'Successfully downloaded {self.old_filename}')

            self._new_file_temp_path = new_file_temp_path
            self._file_bin.append(new_file_temp_path)
        except urllib.error.HTTPError as e:
            print(f'Error: Failed to download {maven_url}')
            raise e
        except Exception as e:
            raise e

    def _empty_file_bin(self) -> None:
        for file_path in self._file_bin:
            try:
                if file_path and os.path.isfile(file_path):
                    os.remove(file_path)
            except:
                # Ignore cleanup errors to preserve an existing exceptions thrown
                pass

    def update(self, dependency_path: str) -> None:
        if self._new_file_temp_path and os.path.isfile(self._new_file_temp_path):
            old_file_path = os.path.join(dependency_path, self.old_filename)
            new_file_path = os.path.join(dependency_path, self.new_filename)

            try:
                shutil.copy2(self._new_file_temp_path, new_file_path)
                
                if os.path.getsize(new_file_path) == os.path.getsize(self._new_file_temp_path):
                    self._file_bin.append(old_file_path)
                    print(f'Successfully updated {self.old_filename} to version {self.new_filename}')
                else:
                    self._file_bin.append(new_file_path)
                    raise ValueError(
                        f'Error: Failed to update {old_file_path}, ' \
                        + \
                        f'the new version {new_file_path} was incorrectly copied to {dependency_path}'
                    )
            except ValueError as e:
                raise e
            except Exception as e:
                self._file_bin.append(new_file_path)
                print(f'Error: Failed to update {old_file_path}')
                raise e
        

class UpdateDependencies:
    @staticmethod
    def _parse_args() -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description='Updates JAR dependencies for an installed application'
        )
        parser.add_argument(
            'dependency_update_json',
            type=str,
            help='Path to a JSON file containing the dependencies to update.'
        )
        parser.add_argument('dependency_path', type=str, help='Path to the application dependencies directory.')

        return parser.parse_args()

    @staticmethod
    def main_cli() -> typing.Literal[1, 0]:
        parsed_args = UpdateDependencies._parse_args()

        with open(parsed_args.dependency_update_json, 'r') as json_fh:
            dependency_list = json.load(json_fh)
        dependency_files = os.listdir(parsed_args.dependency_path)

        for dep_item in dependency_list:
            dep_name = dep_item['name']
            group_path = dep_item['group']
            old_version = dep_item['versions']['old']
            new_version = dep_item['versions']['new']

            # Regex is searching for the following JAR naming format:
            #
            # <library-family-name>-<library-component>-<version>[-<architecture>].jar
            #
            # For example, the regex will match the following two Netty I/O ("netty") libraries:
            #   1. netty-all-4.2.7.Final.jar
            #   2. netty-codec-native-quic-4.2.7.Final-linux-aarch_64.jar
            #
            # The <library-family-name> is "netty" for the above examples
            #
            # In example 1:
            #   <library-component> = "all"
            #   <version> = "4.2.7.Final"
            #
            # In example 2:
            #   <library-component> = "codec-native-quic"
            #   <version> = "4.2.7.Final"
            #   <architecture> = linux-aarch_64
            pattern = rf'^{re.escape(dep_name)}(?:-[^-]+)*-{re.escape(old_version)}(?:-[^-]+)*\.jar$'

            for filename in dependency_files:
                full_path = os.path.join(parsed_args.dependency_path, filename)

                if os.path.isfile(full_path):
                    filename_match = re.match(pattern, filename)
                    if filename_match:
                        try:
                            with DependencyLib(filename, group_path, old_version, new_version) as dependency_lib:
                                dependency_lib.update(parsed_args.dependency_path)
                        except Exception as e:
                            print(e)
                            return 1

        return 0


if __name__ == '__main__':
    sys.exit(UpdateDependencies.main_cli())