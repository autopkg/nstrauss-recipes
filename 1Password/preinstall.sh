#!/bin/bash

user_id="$(scutil <<< 'show State:/Users/ConsoleUser' | awk '($1 == "Name" && $NF == "loginwindow") { exit } ($1 == "UID") { print $NF; exit }')"

old_apps=(
    "/Applications/1Password 6.app"
    "/Applications/1Password 7.app"
    "/Applications/1Password.app"
)

for i in "${old_apps[@]}"; do
    if [[ -d "$i" ]]; then
        /bin/rm -rf "$i"
    fi
done

old_launchd=(
    "2BUA8C4S2C.com.agilebits.onepassword7-helper"
    "com.agilebits.onepassword7-launcher"
)

if [[ ! -z "$user_id" ]]; then
    for l in "${old_launchd[@]}"; do
        /bin/launchctl asuser "$user_id" /bin/launchctl stop "$l"
        /bin/launchctl asuser "$user_id" /bin/launchctl remove "$l"
    done
fi

/usr/bin/killall "1Password"
/usr/bin/killall "1Password 7"
