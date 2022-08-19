#!/usr/bin/env bash

set -e
export TF_IN_AUTOMATION=1

rootdir=$(pwd)
for dir in testdata/terraform/*/*; do
    if [ $dir == "testdata/terraform/zpa/zpa_provisioning_key" ] ||  [ $dir == "testdata/terraform/zia/zia_traffic_forwarding_gre_tunnel" ] ||  [ $dir == "testdata/terraform/zia/zia_user_management" ] ; then
        continue
    fi
    echo "==> $dir (test.tf)"
    cd $dir
    terraform init -backend=false -no-color
    terraform validate -no-color
    cd $rootdir
done