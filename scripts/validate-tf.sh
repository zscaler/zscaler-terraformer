#!/usr/bin/env bash

set -e
export TF_IN_AUTOMATION=1

rootdir=$(pwd)
for dir in testdata/terraform/*; do
    if [ $dir == "testdata/terraform/zpa_app_connector_group" ]; then
        continue
    fi

    echo "==> $dir (test.tf)"
    cd $dir
    terraform init -backend=false -no-color
    terraform validate -no-color
    cd $rootdir
done

for dir in testdata/terraform/*; do
    if [ $dir == "testdata/terraform/zia_firewall_filtering_rule" ]; then
        continue
    fi

    echo "==> $dir (test.tf)"
    cd $dir
    terraform init -backend=false -no-color
    terraform validate -no-color
    cd $rootdir
done
