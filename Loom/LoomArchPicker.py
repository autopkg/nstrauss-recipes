#!/usr/bin/python
#
# Copyright 2021 Nathaniel Strauss
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

from autopkglib import Processor, ProcessorError, URLGetter  # noqa: F401

__all__ = ["LoomArchPicker"]


class LoomArchPicker(URLGetter):
    """Processor to output the download URL of a specificied Loom architecture."""

    description = __doc__
    input_variables = {
        "loom_arch": {"required": False, "default": "x86", "descripton": "x86 or arm64. Defaults to x86.",},
    }
    output_variables = {"loom_url": {"description": "Loom download URL for the specificed arch."}}

    def main(self):
        loom_arch = self.env.get("loom_arch")
        url = "https://www.loom.com/v1/desktop/download/mac"
        response = self.download(url)

        if loom_arch == "x86":
            self.env["loom_url"] = json.loads(response)["urls"][0]
        elif loom_arch == "arm64":
            self.env["loom_url"] = json.loads(response)["urls"][1]
        else:
            self.env["loom_url"] = json.loads(response)["urls"][0] 

        self.output("{}".format(self.env["loom_url"]))


if __name__ == "__main__":
    processor = LoomArchPicker()
    processor.execute_shell()
