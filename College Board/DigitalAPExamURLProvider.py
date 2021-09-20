#!/usr/bin/env python
#
# Copyright 2021 Dan Kuehling, based on work by Allister Banks and Hannes Juutilainen
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

from __future__ import absolute_import

import yaml
import urllib.parse

from autopkglib import Processor, ProcessorError, URLGetter

__all__ = ["DigitalAPExamURLProvider"]

DOWNLOADS_URL = "https://download.app.collegeboard.org/downloads/"
YAML_FILE = "latest-mac.yml"

class DigitalAPExamURLProvider(URLGetter):
    """Provides the download URL for the latest College Board Digital AP Exam app."""

    input_variables = {}
    output_variables = {
        "url": {
            "description": "Download URL for the latest College Board Digital AP Exam app."
        }
    }
    description = __doc__

    def get_url(self, DOWNLOADS_URL, YAML_FILE):
        """"""
        feed_url=DOWNLOADS_URL+YAML_FILE
        try:
            yml = self.download(feed_url)
        except Exception as e:
            raise ProcessorError("Can't download %s: %s" % (feed_url, e))

        root = yaml.safe_load(yml)
        
        # Find the `files` entry that contains `dmg` in what they call the url but is actually the file name
        file_data = next(x for x in root['files'] if 'dmg' in x['url'])
        
        # URL encode the spaces in the filename...thanks College Board!
        filename = urllib.parse.quote(file_data['url']) 
        
        url = DOWNLOADS_URL+filename
        
        return url

    def main(self):
        self.env["url"] = self.get_url(DOWNLOADS_URL, YAML_FILE)
        self.output("Found download URL: %s" % self.env['url'])

if __name__ == "__main__":
    processor = DigitalAPExamURLProvider()
    processor.execute_shell()
