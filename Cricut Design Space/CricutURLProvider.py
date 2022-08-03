#!/usr/local/autopkg/python
#
# Copyright 2020 Nathaniel Strauss
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

import re
from pkg_resources import parse_version
from xml.etree import ElementTree

from autopkglib import Processor, ProcessorError, URLGetter  # noqa: F401

__all__ = ["CricutURLProvider"]

CRICUT_XML_URL = "http://staticcontent.cricut.com/"
CRICUT_BASE_URL = (
    "https://s3-us-west-2.amazonaws.com/staticcontent.cricut.com/a/"
    + "software/osx-native/"
)


class CricutURLProvider(URLGetter):
    """Provides URL to the latest Cricut Design Space version."""

    description = __doc__
    input_variables = {}
    output_variables = {
        "cricut_url": {
            "description": "Latest Cricut Design Space download URL."}
    }

    def tag_uri_and_name(self, elem):
        if elem.tag[0] == "{":
            uri, ignore, tag = elem.tag[1:].partition("}")
        else:
            uri = None
            tag = elem.tag
        return uri, tag

    def main(self):
        # Get release XML
        xml = self.download(CRICUT_XML_URL)
        xml_root = ElementTree.fromstring(xml)

        # Get a list of all download URL chunks
        url_frags = []
        uri = self.tag_uri_and_name(xml_root)[0]
        for frag in list(xml_root.iter("{%s}Key" % uri)):
            if re.search("([0-9\.]+).dmg", frag.text):  # noqa W605
                url_frags.append(frag.text)

        # Strip fragment list to get versions
        cricut_versions = []
        for cricut_version in url_frags:
            try:
                vers_split = re.split("([0-9]+)", cricut_version)[1:6]
            except IndexError:
                pass
            cricut_versions.append("".join(vers_split))

        if cricut_versions:
            sort_vers = sorted(cricut_versions, key=parse_version, reverse=True)
            self.env["cricut_url"] = (
                CRICUT_BASE_URL
                + "Cricut%20Design%20Space%20Install%20v"
                + sort_vers[0]
                + ".dmg"
            )
            self.output("{}".format(self.env["cricut_url"]))
        else:
            raise ProcessorError("Unable to find Cricut version or URL.")


if __name__ == "__main__":
    processor = CricutURLProvider()
    processor.execute_shell()
