#!/usr/bin/python
#
# Copyright 2019 Nathaniel Strauss
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
import json
import urllib

from autopkglib import Processor, ProcessorError  # noqa: F401

__all__ = ["SimpleJSONParser"]


class SimpleJSONParser(Processor):
    """Processor to output specified value of a JSON formatted file."""

    description = __doc__
    input_variables = {
         "json_key": {
            "required": True,
            "descripton": "JSON key value to be parsed.",
        },
        "json_url": {
            "required": True,
            "description": "URL of the JSON to be parsed.",
        },
    }
    output_variables = {
        "json_value": {"description": "JSON value from input key."}
    }

    def main(self):
        url = self.env.get("json_url")
        response = urllib.urlopen(url)
        key = self.env.get("json_key")
        self.env["json_value"] = json.loads(response.read())[key]
        self.output("{}".format(self.env["json_value"]))


if __name__ == "__main__":
    processor = SimpleJSONParser()
    processor.execute_shell()
