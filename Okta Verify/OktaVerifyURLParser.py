#!/usr/local/autopkg/python
#
# Copyright 2022 Nathaniel Strauss
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# With help and inspiration from https://github.com/gabrielsroka/okta_api
# Thank you Gabriel!

import json
import re

from autopkglib import ProcessorError, URLGetter

__all__ = ["OktaVerifyURLParser"]


class OktaVerifyURLParser(URLGetter):
    """Return a valid Okta Verify download URL from the Okta admin Settings > Downloads page."""

    input_variables = {
        "okta_org_id": {
            "required": True,
            "description": "Okta org ID. Everything before .okta.com in the URL.",
        },
        "okta_username": {
            "required": True,
            "description": "Okta username with which to auth.",
        },
        "okta_password": {
            "required": True,
            "description": "Okta password.",
        },
    }
    output_variables = {"okta_verify_url": {"description": "Okta Verify download URL."}}
    description = __doc__

    def prepare_curl_cmd(self, url):
        """Assemble curl command and return it."""
        curl_cmd = super().prepare_curl_cmd()
        self.add_curl_common_opts(curl_cmd)
        curl_cmd.append(url)
        return curl_cmd

    def get_cookie(self, okta_url, session_token):
        """Get the Okta session cookie used to access the downloads page."""
        self.env["curl_opts"] = [
            "-c",
            f"{self.env['RECIPE_CACHE_DIR']}/okta-cookie",
        ]
        curl_cmd = self.prepare_curl_cmd(
            f"{okta_url}/login/sessionCookieRedirect?redirectUrl=/&token={session_token}"
        )
        self.download_with_curl(curl_cmd)

    def get_download_url(self, okta_admin_url):
        """Get the Okta Verify download URL from downloads page."""
        self.env["curl_opts"] = [
            "-b",
            f"{self.env['RECIPE_CACHE_DIR']}/okta-cookie",
        ]
        curl_cmd = self.prepare_curl_cmd(f"{okta_admin_url}/admin/settings/downloads")
        text = self.download_with_curl(curl_cmd)
        match = re.search(r'"(https://.*/artifacts/OKTA_VERIFY_MACOS/.*)"', text)
        if not match:
            raise ProcessorError("Could not find Okta Verify download URL.")
        return match.group(1)

    def get_session_token(self, okta_url, okta_username, okta_password):
        """Return the Okta sign in session token."""
        auth = f'{{"username": "{okta_username}", "password": "{okta_password}"}}'
        self.env["curl_opts"] = [
            "-X",
            "POST",
            "-H",
            "Accept: application/json",
            "-H",
            "Content-Type: application/json",
            "-d",
            f"{auth}",
            "-c",
            f"{self.env['RECIPE_CACHE_DIR']}/okta-cookie",
        ]
        curl_cmd = self.prepare_curl_cmd(f"{okta_url}/api/v1/authn")
        authn = self.download_with_curl(curl_cmd)
        token = json.loads(authn).get("sessionToken")
        if not token:
            raise ProcessorError(
                "Unable to get Okta session token. Check credentials and try again."
            )
        return token

    def main(self):
        okta_org_id = self.env["okta_org_id"]
        okta_username = self.env["okta_username"]
        okta_password = self.env["okta_password"]
        okta_url = f"https://{okta_org_id}.okta.com"
        okta_admin_url = f"https://{okta_org_id}-admin.okta.com"

        session_token = self.get_session_token(okta_url, okta_username, okta_password)
        self.get_cookie(okta_url, session_token)
        self.env["okta_verify_url"] = self.get_download_url(okta_admin_url)


if __name__ == "__main__":
    PROCESSOR = OktaVerifyURLParser()
    PROCESSOR.execute_shell()
