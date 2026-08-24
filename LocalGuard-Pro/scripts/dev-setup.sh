#!/bin/bash
# LocalGuard-Pro Development Setup Script
# Run this script to set up the development environment

set -e  # Exit on error

echo "🔧 LocalGuard-Pro Development Setup"
echo "===================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check Python version
echo -e "${BLUE}Checking Python version...${NC}"
PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
REQUIRED_VERSION="3.10"

if ! python3 -c "import sys; exit(0 if sys.version_info >= (3, 10) else 1)"; then
    echo -e "${RED}❌ Python 3.10+ required. Found: $PYTHON_VERSION${NC}"
    exit 1
fi
echo -e "${GREEN}✅ Python $PYTHON_VERSION${NC}"

# Create virtual environment
if [ ! -d ".venv" ]; then
    echo -e "${BLUE}Creating virtual environment...${NC}"
    python3 -m venv .venv
    echo -e "${GREEN}✅ Virtual environment created${NC}"
else
    echo -e "${YELLOW}⚠️  Virtual environment already exists${NC}"
fi

# Activate virtual environment
echo -e "${BLUE}Activating virtual environment...${NC}"
source .venv/bin/activate

# Upgrade pip
echo -e "${BLUE}Upgrading pip...${NC}"
pip install --upgrade pip

# Install runtime dependencies
echo -e "${BLUE}Installing runtime dependencies...${NC}"
pip install -r requirements.txt

# Install development dependencies
echo -e "${BLUE}Installing development dependencies...${NC}"
pip install -r requirements-dev.txt

# Install pre-commit hooks
echo -e "${BLUE}Installing pre-commit hooks...${NC}"
pre-commit install

# Create config if not exists
if [ ! -f "localguard.yaml" ] && [ ! -f ".localguard.yaml" ]; then
    echo -e "${BLUE}Creating default config...${NC}"
    cp .localguard.yaml.example .localguard.yaml
    echo -e "${GREEN}✅ Created .localguard.yaml from example${NC}"
else
    echo -e "${YELLOW}⚠️  Config file already exists${NC}"
fi

# Run initial tests
echo -e "${BLUE}Running initial tests...${NC}"
if pytest tests/ -v --tb=short -q; then
    echo -e "${GREEN}✅ All tests passed${NC}"
else
    echo -e "${YELLOW}⚠️  Some tests failed (expected in early development)${NC}"
fi

# Verify CLI works
echo -e "${BLUE}Verifying CLI...${NC}"
if localguard --help > /dev/null 2>&1; then
    echo -e "${GREEN}✅ CLI working${NC}"
else
    echo -e "${RED}❌ CLI not working${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}🎉 Setup Complete!${NC}"
echo ""
echo "Next steps:"
echo "  1. Activate venv: source .venv/bin/activate"
echo "  2. Run scan: localguard scan --target http://localhost:8000 --project-root ."
echo "  3. Run tests: pytest tests/ -v"
echo "  4. Lint code: ruff check . && mypy localguard/"
echo ""
echo "Happy hacking! 🔒"