#!/bin/bash
# LocalGuard-Pro Quick Install Script
# Installs LocalGuard-Pro globally via pipx or in user space

set -e

echo "📦 LocalGuard-Pro Quick Install"
echo "================================"

# Check if pipx is available
if command -v pipx &> /dev/null; then
    echo "Installing via pipx..."
    pipx install git+https://github.com/localguard/localguard-pro.git
    echo "✅ Installed via pipx"
    echo "Run: localguard --help"
    exit 0
fi

# Check if pip is available
if command -v pip3 &> /dev/null; then
    echo "Installing via pip (user)..."
    pip3 install --user git+https://github.com/localguard/localguard-pro.git
    echo "✅ Installed via pip"
    echo "Make sure ~/.local/bin is in your PATH"
    echo "Run: localguard --help"
    exit 0
fi

echo "❌ Neither pipx nor pip3 found. Please install Python and pip first."
exit 1