Cricut Design Space installer app uses osascript in its postinstall which triggers PPPC on Mojave and above. I tried to include another postinstall script in the package originally, but it conflicted with osascript and I was unable to sort out a working PPPC profile. 

As a result the postinstall isn't included, but remains in the repo since it can be used within Jamf Pro, Munki, or other management solution after package install.

In Jamf Pro that would mean including the script after package install within a policy.