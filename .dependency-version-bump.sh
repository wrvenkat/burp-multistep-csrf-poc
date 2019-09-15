#!/bin/bash

# This script is run to trigger a new build so as to pull in updates to request_parser and request_generator.
# This script bumps the patch version, adds this new version to .dependecy.version, commits and tags the commit with that version which triggers a new build.

current_version=$(git tag --sort=committerdate | tail -n1)
patch_version=$(echo $current_version | cut -d'.' -f3)

if [ -z $patch_version ]; then
    patch_version=0
fi

new_patch_version=$((patch_version+1)) &&\
new_version=$(git tag --sort=committerdate | tail -n1 | awk -F'.' '{print $1"."$2"."}') &&\
new_version="$new_version""$new_patch_version" &&\
#printf "New Version: %s" "$new_version"
echo "$new_version" >> .dependency.version &&\
git config user.email "wrvenkat@gmail.com" && git config user.name "Venkat Raman" &&\
git add .dependency.version &&\
git commit -m "Dependency update version bump." &&\
git tag "$new_version" &&\
git push --tags
