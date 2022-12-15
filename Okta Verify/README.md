# Okta Verify recipes
The Okta Verify recipes use a custom `OktaVerifyURLParser` processor in order to get the download URL. It auths to the Okta API to get a session token, which is then used to get a cookie, which in turn accesses the Okta admin portal page at Settings > Downloads.

Since the only piece of relevant information is the Okta Verify download URL, **do not use a production instance with credentials which could access sensitive data**. Instead, register a free Okta developer account, with a throwaway or aliased email, at [https://developer.okta.com/signup/](https://developer.okta.com/signup/). Use credentials generated from the new dev instance, or potentially a sandbox instance if your org already has one.

It is required to supply `OKTA_ORG_ID` (everything before `.okta.com`), `OKTA_USERNAME`, and `OKTA_PASSWORD`, and recommended these are defined in a recipe override. AutoPkg in no way protects the `OKTA_PASSWORD` variable and it should not be considered secret.

In the future this processor could be generalized to download other Okta software gated behind auth. However, in an even better future Okta would post these publicly with a static download URL, removing the need for an additional processor at all. Please upvote this feature request if you feel the same. [https://ideas.okta.com/app/#/case/154890](https://ideas.okta.com/app/#/case/154890)

Credit to Gabriel Sroka ([https://github.com/gabrielsroka/okta_api](https://github.com/gabrielsroka/okta_api)) for guidance and help.