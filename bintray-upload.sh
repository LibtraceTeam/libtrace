#!/bin/bash

set -x -e -o pipefail

apt-get update && apt-get install -y curl

for path in `find built-packages/amd64/ -maxdepth 1 -type d`; do
    IFS=_ read linux_dist linux_version <<< $(basename "${path}")
    for deb in `find "${path}" -maxdepth 1 -type f`; do
        pkg_filename=$(basename "${deb}")
        IFS=_ read pkg_name pkg_version pkg_arch <<< $(basename -s ".deb" "${pkg_filename}")
        curl -T "${deb}" -u${BINTRAY_USERNAME}:${BINTRAY_API_KEY} \
            "https://api.bintray.com/content/wand/libtrace/${pkg_name}/${pkg_version}/pool/${linux_version}/main/${pkg_filename};deb_distribution=${linux_version};deb_component=main;deb_architecture=${pkg_arch}"
    done
done
