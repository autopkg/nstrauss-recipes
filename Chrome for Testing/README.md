# Chrome for Testing
Chrome for Testing recipes use Google provided JSON API endpoints to get version and release channel information. In most cases, set `DOWNLOAD_VERSION` to "latest" and `RELEASE_CHANNEL` to one of `Stable`, `Beta`, `Dev`, or `Canary` to get the corresponding version. However, in the spirit of testing against pinned versions, the download recipe can also use a static string input variable.

Binaries are not universal and as such an architecture still needs to be specified. At this time Chrome for Testing is only adhoc code signed. There is no code signature verification in place.

### What it is and isn't

> Designed to solve these problems, Chrome for Testing is a dedicated flavor of Chrome targeting the testing use case, without auto-update, integrated into the Chrome release process, made available for every Chrome release. A versioned binary that’s as close to regular Chrome as possible without negatively affecting the testing use case.

> Chrome for Testing has been created purely for browser automation and testing purposes, and is not suitable for daily browsing.

### References
https://developer.chrome.com/blog/chrome-for-testing/  
https://github.com/GoogleChromeLabs/chrome-for-testing  
https://github.com/GoogleChromeLabs/chrome-for-testing#json-api-endpoints
