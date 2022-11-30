## Custom processor note

`ditto` fails to unpack Drive's pkg payload as necessary. Using `aa` with a custom processor instead which is a direct copy of https://github.com/autopkg/autopkg/pull/804. As soon as Graham's work is merged into main and a new release is cut, this custom processor will be removed in favor of the built in autopkg lib.