#!/bin/bash

echo "=== Building terraformer binary ==="
go build -o zscaler-terraformer .

echo ""
echo "=== Test 1: Generate command only (no terraform imports) ==="
echo "This tests just the API calls to get segment groups"

mkdir -p /tmp/test1
cd /tmp/test1

export ZSCALER_SDK_LOG=true
export ZSCALER_SDK_VERBOSE=true

timeout 120s /Users/wguilherme/go/src/github.com/zscaler/hashicorp-terraform/zscaler-terraformer/zscaler-terraformer generate --resources zpa_segment_group --no-progress

if [ $? -eq 124 ]; then
    echo "❌ Generate command timed out - API call is hanging"
else
    echo "✅ Generate command completed - API calls work!"
    echo "Generated files:"
    ls -la
fi

echo ""
echo "=== Test 2: Terraform init only ==="
echo "This tests if terraform can initialize in Docker environment"

cd /tmp
mkdir -p test2
cd test2

cat > main.tf << EOF
terraform {
  required_providers {
    zpa = {
      source = "zscaler/zpa"
    }
  }
}

provider "zpa" {}
EOF

timeout 120s terraform init -no-color

if [ $? -eq 124 ]; then
    echo "❌ Terraform init timed out - network/terraform issue in Docker"
else
    echo "✅ Terraform init completed"
fi

echo ""
echo "=== Test 3: Simple terraform import test ==="
echo "This tests if terraform import hangs even with fake data"

cat > resource.tf << EOF
resource "zpa_segment_group" "test" {
  name = "test"
  description = "test"
  enabled = true
}
EOF

timeout 60s terraform import -no-color zpa_segment_group.test fake-id

if [ $? -eq 124 ]; then
    echo "❌ Terraform import timed out - THIS IS THE ISSUE!"
else
    echo "✅ Terraform import completed (even if it failed, it didn't hang)"
fi

echo ""
echo "=== Cleanup ==="
cd /Users/wguilherme/go/src/github.com/zscaler/hashicorp-terraform/zscaler-terraformer
rm -rf /tmp/test1 /tmp/test2
rm -f zscaler-terraformer

echo "=== Debug test completed ==="