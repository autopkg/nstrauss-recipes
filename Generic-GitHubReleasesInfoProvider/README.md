# Generic recipes

Generic recipes are those which do nothing by themselves and are intended to be templates to be filled out in overrides. These types of recipes were born of out two main goals.

1. Many autopkg patterns repeat themselves and are not specific enough to warrant an entirely new recipe. For example, processors are usually the same for a package download with static URL.
2. Avoid dealing with private repos. Typically, organizations will keep an internal, private recipe repo as well to deal with scenarios where secrets and other sensitive data can't be shared publicly. Generic, generalized recipes mean those secrets only need to exist in overrides.

These may or may not fit your use case. Create an override, fill out or add input variables as needed, and change identifier/recipe names.
