Cricut Design Space installer app uses osascript in its postinstall which triggers PPPC on Mojave and above. I tried to include another postinstall script in the pack originally, but it conflicted with osascript and I was unable to sort out a working PPPC profile. 

As a result the postinstall isn't included as part of the package, but is staying in the repo since it can be used as a script within Jamf Pro, Munki, or other management solution once the package itself copies the installer app to /private/tmp.

In Jamf Pro that would mean including the script after package install within a policy.