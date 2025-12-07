#!/usr/local/autopkg/python
#
# Copyright 2020 Andrew Zirkel
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

import subprocess

from autopkglib import Processor


class LightspeedRelaySmartAgentVersioner(Processor):
    description = "Get Relay Smart Agent version via mobilefilter binary"
    input_variables = {
        "mobilefilter_path": {
            "required": True,
            "description": "path to mobilefilter binary.",
        },
    }
    output_variables = {
        "version": {
            "description": "Version of mobilefilter binary.",
        },
    }

    __doc__ = description

    def main(self):
        mobilefilter_path = self.env["mobilefilter_path"]

        version = subprocess.check_output([mobilefilter_path, "-v"]).decode().rstrip()
        self.env["version"] = version
        self.output("Found version %s" % (self.env["version"]))


if __name__ == "__main__":
    processor = LightspeedRelaySmartAgentVersioner()
    processor.execute_shell()
