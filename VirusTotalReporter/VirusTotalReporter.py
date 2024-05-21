#!/usr/local/autopkg/python

# MIT License

# Copyright (c) 2024 Nathaniel Strauss

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import hashlib
import json
import os
import ssl
import subprocess
import time
from urllib.error import URLError
from urllib.request import HTTPErrorProcessor, HTTPSHandler, Request, build_opener

import certifi
from autopkglib import Processor, ProcessorError, find_binary

__all__ = ["VirusTotalReporter"]


class NoExceptionHTTPErrorProcessor(HTTPErrorProcessor):
    def http_response(self, request, response):
        return response

    https_response = http_response


class VirusTotalReporter(Processor):
    """Get VirusTotal detection report data for a given file."""

    input_variables = {
        "VIRUSTOTAL_API_KEY": {
            "default": "3858a94a911f47707717f6d090dbb8f86badb750b0f7bfe74a55c0c6143e3de6",
            "required": False,
            "description": "VirusTotal API key used to make requests.",
        },
        "VIRUSTOTAL_ALWAYS_REPORT": {
            "default": False,
            "required": False,
            "description": (
                "Always get a report from VirusTotal, not only on new downloads. "
                "Not recommended as it can lead to rate limiting with longer recipe lists.",
            ),
        },
        "VIRUSTOTAL_SKIP": {
            "default": False,
            "required": False,
            "description": (
                "Skip this processor entirely. Most often used in situations where "
                "a file is internal only, contains potentially sensitive organization specific data,"
                "or otherwise doesn't need to be analyzed.",
            ),
        },
        "VIRUSTOTAL_SUBMIT_NEW": {
            "default": False,
            "required": False,
            "description": "When a file isn't already in VirusTotal's database, submit it for analysis. 650 MB file size limit.",
        },
        "pathname": {
            "required": False,
            "description": "File path to analyze.",
        },
        "output_full_report": {
            "default": False,
            "required": False,
            "description": "Output the full VirusTotal report to the recipe result plist.",
        },
        "json_report_path": {
            "default": None,
            "required": False,
            "description": "Write the full VirusTotal report to JSON at the configured path.",
        },
        "submission_timeout": {
            "default": 300,
            "required": False,
            "description": "Timeout in seconds to wait for a newly submitted file report to be generated.",
        },
    }
    output_variables = {
        "virus_total_analyzer_summary_result": {
            "description": "VirusTotal report data."
        },
    }
    description = __doc__

    def api_key(self) -> str:
        """Get the VirusTotal API from environment variable."""
        return self.env.get("VIRUSTOTAL_API_KEY", None)

    def default_ssl_context(self):
        """Create a SSL context with certifi for use with urllib."""
        return ssl.create_default_context(cafile=certifi.where())

    def curl_binary(self) -> str:
        """Return a path to a curl binary, priority in the order below.
        Return None if none found.
        1. env["CURL_PATH"]
        2. app pref "CURL_PATH"
        3. a "curl" binary that can be found in the PATH environment variable
        4. "/usr/bin/curl" (POSIX-y platforms only)

        Borrowed from URLGetter
        https://github.com/autopkg/autopkg/blob/8a12727820da6be40ee27530ac492c30283e54ca/Code/autopkglib/URLGetter.py#L37C1-L50C76
        """
        curlbin = find_binary("curl", self.env)
        if curlbin is not None:
            return curlbin

        raise ProcessorError("Unable to locate or execute any curl binary.")

    def virustotal_api_v3(self, endpoint: str) -> dict:
        """Get data from the VirusTotal API using a specified endpoint."""
        url = f"https://www.virustotal.com/api/v3{endpoint}"

        https_handler = HTTPSHandler(context=self.default_ssl_context())
        opener = build_opener(https_handler, NoExceptionHTTPErrorProcessor())
        request = Request(url, headers={"x-apikey": self.api_key()})

        try:
            response = opener.open(request, timeout=30)
        except URLError as err:
            raise ProcessorError(f"Failed to reach VirusTotal server: {err.reason}")
        except TimeoutError:
            raise ProcessorError("VirusTotal API response timed out.")

        return response.read(), response.status
        # return {"http_status_code": response.status, "response": response.read()}

    def curl_new_file(self, input_path: str) -> dict:
        """
        Use `curl` to submit a new file for analysis using the VirusTotal API.
        urllib's support for multipart form data is minimal and not worth grokking.

        First get a one time upload URL to support a max file size limit of 650 MB.
        """
        data, _ = self.virustotal_api_v3("/files/upload_url")
        upload_url = self.load_api_json(data, "data")
        cmd = [
            self.curl_binary(),
            "--request",
            "POST",
            "--url",
            upload_url,
            "--header",
            "accept: application/json",
            "--header",
            "content-type: multipart/form-data",
            "--header",
            f"x-apikey: {self.api_key()}",
            "--form",
            f"file=@{input_path}",
        ]

        try:
            submit = subprocess.run(cmd, capture_output=True, check=True, text=True)
        except subprocess.CalledProcessError as err:
            self.output(f"ERROR: {err.stderr.removeprefix('curl: ')}")
            raise ProcessorError(err.stderr) from err

        return submit.stdout

    def submit_new_file(self, input_path: str, sha256: str):
        """
        Submit a new file for analysis and wait for the report to complete.
        Default timeout is 5 minutes. Timeout length can be configured with submission_timeout.
        """
        self.output(f"Submitting new file for analysis: {input_path} ({sha256})")
        submission = self.curl_new_file(input_path)
        analysis_url = self.load_api_json(submission, "data")["links"]["self"]

        timer = 0
        while True:
            time.sleep(30)
            timer += 30
            if timer > self.env.get("submission_timeout"):
                raise ProcessorError(
                    f"New file submission timed out waiting for analysis to complete. "
                    "Check report status at https://www.virustotal.com/gui/file/{sha256}"
                )
            self.output(f"Waiting for new file analysis to complete: {timer} seconds.")

            analysis_status, analysis_status_code = self.virustotal_api_v3(
                analysis_url.split("v3")[1]
            )
            if (
                analysis_status_code == 200
                and self.load_api_json(analysis_status, "data")["attributes"]["status"]
                == "completed"
            ):
                self.output("Analysis complete. Attempting to get generated report.")
                break

    def get_sha256(self, file_path: str) -> str:
        """Get the SHA-256 hash of a file."""
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as file:
            for chunk in iter(lambda: file.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

    def load_api_json(self, data: dict, top_level: str) -> dict:
        """Convert a VirusTotal API response to JSON object."""
        try:
            return json.loads(data)[top_level]
        except KeyError:
            raise ProcessorError(
                "Couldn't get VirusTotal API data. Most likely malformed response."
            )

    def process_summary_results(self, report: dict, input_path: str, sha256: str):
        """Write VirusTotal report data."""
        data = self.load_api_json(report, "data")
        last_analysis_stats = data.get("attributes").get("last_analysis_stats")
        harmless = last_analysis_stats.get("harmless", 0)
        malicious = last_analysis_stats.get("malicious", 0)
        suspicious = last_analysis_stats.get("suspicious", 0)
        undetected = last_analysis_stats.get("undetected", 0)
        total_detected = str(harmless + malicious + suspicious)
        total = str(harmless + malicious + suspicious + undetected)

        self.env["virus_total_analyzer_summary_result"] = {
            "summary_text": "The following items were queried from the VirusTotal database:",
            "report_fields": [
                "name",
                "detections",
                "ratio",
                "permalink",
            ],
            "data": {
                "name": os.path.basename(input_path),
                "detections": total_detected,
                "harmless": harmless,
                "malicious": malicious,
                "suspicious": suspicious,
                "undetected": undetected,
                "ratio": f"{total_detected}/{total}",
                "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
            },
        }
        if self.env.get("output_full_report"):
            self.env["virus_total_analyzer_summary_result"]["data"][
                "full_report"
            ] = data
        self.write_json_report(data)

    def write_json_report(self, data: dict):
        """Optionally Write the full VirusTotal report to JSON at the configured path."""
        if self.env.get("json_report_path"):
            with open(self.env.get("json_report_path"), "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=4)

    def main(self):
        if self.env.get("VIRUSTOTAL_SKIP", False):
            self.output(
                f"VIRUSTOTAL_SKIP set to {self.env.get('VIRUSTOTAL_SKIP')}. Skipping processor."
            )
            return

        input_path = self.env.get("pathname", None)
        if not input_path:
            self.output("pathname empty. No file found to analyze. Skipping processor.")
            return

        if not self.env.get("download_changed") and not self.env.get(
            "VIRUSTOTAL_ALWAYS_REPORT"
        ):
            self.output("No new downloads. Skipping processor.")
            return

        file_sha256 = self.get_sha256(input_path)
        report, report_status_code = self.virustotal_api_v3(f"/files/{file_sha256}")

        if report_status_code == 200:
            self.process_summary_results(report, input_path, file_sha256)
            return

        # When there's no matching file in the VirusTotal database, submit new if configured
        error = self.load_api_json(report, "error")
        if (
            report_status_code == 404
            and error.get("code") == "NotFoundError"
            and self.env["VIRUSTOTAL_SUBMIT_NEW"]
        ):
            if round(os.path.getsize(input_path) / (1024 * 1024.0), 2) > 650:
                self.output(
                    "WARNING: File is over 650 MB and too large to submit to VirusTotal for analysis. Skipping."
                )
                return

            self.submit_new_file(input_path, file_sha256)
            report, _ = self.virustotal_api_v3(f"/files/{file_sha256}")
            self.process_summary_results(report, input_path, file_sha256)
            return

        # No report for file found and not configured to submit new
        if report_status_code == 404:
            self.output(
                f"WARNING: No match found for {os.path.basename(input_path)} in VirusTotal database. "
                "Submission for new files is turned off by default. Set VIRUSTOTAL_SUBMIT_NEW to analyze and report on new files. "
                "No results will be included in this run."
            )
            return

        # Should never get here - an error occurred
        raise ProcessorError(
            f"VirusTotal API call failed. {report_status_code}: {error.get('code')}. {error.get('message')}."
        )


if __name__ == "__main__":
    PROCESSOR = VirusTotalReporter()
    PROCESSOR.execute_shell()
