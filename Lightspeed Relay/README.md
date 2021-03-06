# Lightspeed Relay Smart Agent
Lightspeed's documentation only provides a DMG method to mount and install the containing package. This is an alternative package installer which takes required files from the mounted DMG and repackages. Keep in mind this is not directly supported by Lightspeed, and they may not be able to help if something goes wrong. This package has been tested on thousands of Macs without a problem. 

1. Download the latest DMG from the Relay admin portal. 
2. `autopkg run RelaySmartAgent.pkg.recipe --key AGENT_DMG="/path/to/SmartAgent.dmg"`
3. Profit!

There is no download recipe as the URL changes on each release and targeting a DMG also allows repackaging beta or prerelease versions. LightspeedRelaySmartAgentVersioner runs the `mobilefilter` binary to get the version and was stolen from [andrewzirkel-recipes](https://github.com/autopkg/andrewzirkel-recipes/tree/master/LightspeedRelaySmartAgent). Thanks Andrew! Nothing wrong with those recipes, but they still use a DMG wrapped in a package. This recipe is a straight package alternative.

## Kextless Recipe
The kextless recipe is meant to be used with smart agent version 1.5.0 or later. It provides initial Big Sur compatibility. 1.5.0+ without the kext installed also significantly improves download speeds. There was previously an issue that bottleknecked downloads at around 50 Mbps or degraded slower connections even further. From Relay's release notes...

- Adds Big Sur compatibility by allowing the Smart Agent components to continue filtering browser requests without the use of Apple’s deprecated kernel extensions. 
- Note: Due to the deprecation of Apple’s filtering kernel extensions, the Smart Agent will only ensure filtering for applications that honor the system proxy settings.

Some applications without proxy support might not be filtered. Depending on your environment, that may be a good or bad thing.