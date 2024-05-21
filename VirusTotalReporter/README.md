# VirusTotalReporter
`VirusTotalReporter` is a processor designed to return file report information from VirusTotal. Heavily inspired by the well loved and widely used [`VirusTotalAnalyzer`](https://github.com/hjuutilainen/autopkg-virustotalanalyzer) by Hannes Juutilainen, `VirusTotalReporter`'s goal is to provide as much detection data as possible to make informed decisions within AutoPkg recipes and workflows. It is for the most part a drop-in replacement for `VirusTotalAnalyzer`, and includes the same output variables in the same format. 

Why use `VirusTotalReporter` over `VirusTotalAnalyzer`?
- Significant improvements to reporting for new files. `VirusTotalReporter` will optionally submit new files not already in the VirusTotal database, wait for analysis, and returns results in the same run. `VirusTotalAnalyzer` only submits new files, not report on them.  
- Supports outputting the full VirusTotal report to a recipe's report property list or specificied JSON file.
- Uses VirusTotal's v3 API. The v2 API is deprecated and in some cases provides fewer details or less specific data.

### Recipe usage
```yaml
Input:
  NAME: Firefox
  VIRUSTOTAL_SUBMIT_NEW: true

Process:
  - Processor: com.github.nstrauss.VirusTotalReporter/VirusTotalReporter
    Arguments:
      output_full_report: true
      json_report_path: "%RECIPE_CACHE_DIR%/%NAME%_virustotal.json"
```

### Command line post-processor usage
```bash
autopkg run Firefox.munki --post com.github.nstrauss.VirusTotalReporter/VirusTotalReporter
```
```bash
autopkg run Firefox.munki --post com.github.nstrauss.VirusTotalReporter/VirusTotalReporter --key VIRUSTOTAL_SUBMIT_NEW=True
```

## Submitting new files
By default, `VirusTotalReporter` does not submit new files for analysis. If there's not already a matching SHA-256 for a file in the VirusTotal database, no results are returned. The intention is to not inadvertently submit files to a public database which are private to your organization - internal only tools, registration tokens, etc. However, it is encouraged new files be submitted for two reasons.

1. Including analysis only for already submitted files could mean a sizable coverage gap. In workflows where trust and import/upload decisions are made based on VirusTotal detections, files which have never been analyzed are assumed safe, even when they may not be.
1. The VirusTotal [license](https://docs.virustotal.com/reference/public-vs-premium-api) requires businesses using the free, public API to contribute new files.

In order to submit new files, set `VIRUSTOTAL_SUBMIT_NEW` to true. On submission, `VirusTotalReporter` will check every 30 seconds whether file analysis has completed and then return detection results in the same run. Timeout length is 5 minutes and can be configured with `submission_timeout`. The max file size limit is 650 MB.

## VirusTotal API keys
A community API key is included. To use your own key, follow the [getting started](https://docs.virustotal.com/reference/getting-started) guide to register an account. `VIRUSTOTAL_API_KEY` can be set to use the account specific key.

## Skipping VirusTotal analysis
Set `VIRUSTOTAL_SKIP` in a recipe override's input variables to skip the processor completely and never interact with VirusTotal's API. Most often used in situations where a file is internal only, contains potentially sensitive organization specific data, or otherwise doesn't need to be analyzed.

```xml
<key>Input</key>
<dict>
    <key>NAME</key>
    <string>Firefox</string>
    <key>SKIP_VIRUSTOTAL</key>
    <string>true</string>
</dict>
```
```yaml
Input:
    NAME: Firefox
    SKIP_VIRUSTOTAL: true
```

## Saving full report data
Though by default only detection values are included, the full, unredacted report direct from the VirusTotal API is available either through summary results or by writing JSON to a configured path. Set `output_full_report` to include in a recipe's report plist in `virus_total_analyzer_summary_result`. Set `json_report_path` to generate a JSON a report. When using `json_report_path` as a command line argument like `--key json_report_path=/my/full/path/report.json`, an absolute path must be used.

## curl
There is support for `URLGetter`'s method of finding and defining the path to a `curl` binary. `CURL_PATH` can be set to use a custom path. 

https://github.com/autopkg/autopkg/wiki/Downloading-from-the-Internet-in-Custom-Processors#figuring-out-where-curl-is

## TODO
- Implement retries for rate limiting with backoff period.
