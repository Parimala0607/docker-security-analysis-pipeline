#!/usr/bin/env bash
# scripts/install_tools.sh — Install all scanner tools on Ubuntu 22.04
# Run once: bash scripts/install_tools.sh

set -euo pipefail

echo "Installing Trivy..."
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
  | sh -s -- -b /usr/local/bin

echo "Installing Grype..."
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
  | sh -s -- -b /usr/local/bin

echo "Installing Syft..."
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
  | sh -s -- -b /usr/local/bin

echo "Installing Dockle..."
VERSION=$(curl -s https://api.github.com/repos/goodwithtech/dockle/releases/latest \
  | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
curl -sSfL "https://github.com/goodwithtech/dockle/releases/download/v${VERSION}/dockle_${VERSION}_Linux-64bit.tar.gz" \
  | tar xz -C /usr/local/bin dockle

echo "Verifying..."
for cmd in trivy grype syft dockle; do
  $cmd --version | head -1
done

echo "All tools installed."
