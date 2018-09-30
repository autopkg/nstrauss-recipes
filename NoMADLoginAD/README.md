# NoMADLoginAD.pkg.recipe
Put together a quick recipe to help test out Mac DEP workflows using Jamf Pro
and NoMADLoginAD. 

This recipe has been updated to use `authchanger` instead of `security
authorizationdb write system.login.console` referencing a text file on disk. 

1. Download the latest version of NoMAD Login AD from https://files.nomad.menu/NoMAD-Login-AD.zip
2. Run  NoMADLogin-x.x.pkg - the non-authchanger installer package. 
2. Open this recipe's /scripts/postinstall in your favorite text editor to change preferences as you'd like (https://gitlab.com/orchardandgrove-oss/NoMADLogin-AD/wikis/Configuration/preferences). Add, remove, or comment out preferences as needed. Note `defaults write` commands are used in favor of a profile when using Jamf Pro due to lack of await configuration support. As a result, profiles might not be installed by the time NoMAD Login launches. 
3. Run the recipe. 
4. Include in the first enrollment complete policy to kick off during your DEP
   workflow. 

