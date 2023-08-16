#!/usr/local/autopkg/python
#
# Copyright 2023 Nathaniel Strauss
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json

from autopkglib import Processor, ProcessorError, URLGetter  # noqa: F401

__all__ = ["ChromeforTestingURLProvider"]

KNOWN_GOOD_VERSIONS = "https://googlechromelabs.github.io/chrome-for-testing/known-good-versions-with-downloads.json"
LAST_KNOWN_GOOD_VERSIONS = "https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json"


class ChromeforTestingURLProvider(URLGetter):
    """Processor to output the specified Chrome for Testing download URL."""

    description = __doc__
    input_variables = {
        "channel": {
            "required": False,
            "descripton": "Specify release channel when using 'latest' from chrome_version - Stable, Beta, Dev, Canary.",
        },
        "chrome_arch": {
            "required": True,
            "descripton": "arm64 or x64.",
        },
        "chrome_version": {
            "required": True,
            "descripton": "Use 'latest' or a specific version string.",
        },
    }
    output_variables = {
        "chrome_download_url": {
            "description": "The download URL for the specified version."
        },
    }

    def main(self):
        channel = self.env.get("channel")
        arch = self.env.get("chrome_arch")
        desired_version = self.env.get("chrome_version")
        download_url = []

        if desired_version == "latest":
            feed = json.loads(self.download(LAST_KNOWN_GOOD_VERSIONS))
            download_url = "".join(
                [
                    d["url"]
                    for d in feed["channels"][channel]["downloads"]["chrome"]
                    if d["platform"] == f"mac-{arch}"
                ][0]
            )
        else:
            feed = json.loads(self.download(KNOWN_GOOD_VERSIONS))
            downloads = [d for d in feed["versions"] if d["version"] == desired_version]
            if not downloads:
                raise ProcessorError(
                    f"No known good versions matching {desired_version}. Check to make sure chrome_version is valid."
                )
            download_url = "".join(
                [
                    u["url"]
                    for u in downloads[0]["downloads"]["chrome"]
                    if u["platform"] == f"mac-{arch}"
                ][0]
            )

        if not download_url:
            raise ProcessorError(
                f"No valid download URL found for version {desired_version}"
            )

        self.env["chrome_download_url"] = download_url
        self.output(f"Chrome for Testing download URL: {download_url}")


if __name__ == "__main__":
    processor = ChromeforTestingURLProvider()
    processor.execute_shell()
