# NoMADLoginAD.pkg.recipe
Put together a quick recipe to help test out Mac DEP workflows using Jamf Pro and NoMADLoginAD. 

1. Copy the latest build of NoMADLoginAD.bundle (https://gitlab.com/macshome/NoMADLogin-AD) to /Library/Security/SecurityAgentPlugins
2. Open /scripts/postinstall in your favorite text editor to change preferences as you'd like (https://gitlab.com/macshome/NoMADLogin-AD/wikis/preferences)
    * Change AD_domain variable which sets the ADDomain preference key 
    * Set SSL variable to true to enable
3. Run the recipe
4. Include in the first enrollment complete policy to kick off during your DEP workflow

