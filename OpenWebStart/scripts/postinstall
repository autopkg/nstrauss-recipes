#!/bin/zsh

tmp="/private/tmp"

# Run installer
"$tmp"/OpenWebStart.app/Contents/MacOS/JavaApplicationStub -q -varfile "$tmp"/response.varfile

# Clean up installer and varfile
rm -rf "$tmp"/OpenWebStart.app
rm -rf "$tmp"/response.varfile
