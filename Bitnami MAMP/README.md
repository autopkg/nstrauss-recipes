Postinstall script is only provided as an example and not included in package recipe. In this example the goal is to allow standard users to install and manage MAMP without admin rights.

If using Jamf Pro can be included as an after script in the package install policy. Other management solutions can use a similar method. Can also be included directly in the package recipe by including an override with scripts key.

To get a list of all options...

`/private/tmp/MAMP.app/Contents/MacOS/osx-x86_64 --help`
