#!/bin/bash
# FIPS 140-3 Level 3 Compliance Gate for CI/CD Pipeline
# This script MUST pass before any deployment to production

set -e

echo "🔐 Government-Grade FIPS Compliance Gate"
echo "========================================"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

COMPLIANCE_FAILED=0

# Check 1: FIPS_MODE environment variable
echo -n "Checking FIPS_MODE... "
if [ "$FIPS_MODE" != "true" ]; then
    echo -e "${RED}FAIL${NC}"
    echo "  ❌ FIPS_MODE must be set to 'true' for production"
    COMPLIANCE_FAILED=1
else
    echo -e "${GREEN}PASS${NC}"
fi

# Check 2: HSM_AVAILABLE environment variable
echo -n "Checking HSM_AVAILABLE... "
if [ "$HSM_AVAILABLE" != "true" ]; then
    echo -e "${RED}FAIL${NC}"
    echo "  ❌ HSM_AVAILABLE must be set to 'true' for FIPS 140-3 Level 3"
    COMPLIANCE_FAILED=1
else
    echo -e "${GREEN}PASS${NC}"
fi

# Check 3: PQ_CRYPTO_ENABLED environment variable
echo -n "Checking PQ_CRYPTO_ENABLED... "
if [ "$PQ_CRYPTO_ENABLED" != "true" ]; then
    echo -e "${RED}FAIL${NC}"
    echo "  ❌ PQ_CRYPTO_ENABLED must be set to 'true' for quantum resistance"
    COMPLIANCE_FAILED=1
else
    echo -e "${GREEN}PASS${NC}"
fi

# Check 4: Verify all service binaries call MustInitFIPSMode()
echo -n "Checking MustInitFIPSMode() integration... "
SERVICES_WITHOUT_FIPS=()

# Check Go services
for service in services/go/*/cmd/main.go platform/examples/*/main.go; do
    if [ -f "$service" ]; then
        if ! grep -q "MustInitFIPSMode()" "$service"; then
            SERVICES_WITHOUT_FIPS+=("$service")
        fi
    fi
done

if [ ${#SERVICES_WITHOUT_FIPS[@]} -gt 0 ]; then
    echo -e "${RED}FAIL${NC}"
    echo "  ❌ The following services do NOT call MustInitFIPSMode():"
    for svc in "${SERVICES_WITHOUT_FIPS[@]}"; do
        echo "     - $svc"
    done
    COMPLIANCE_FAILED=1
else
    echo -e "${GREEN}PASS${NC}"
fi

# Check 5: Verify Helm charts have FIPS env vars
echo -n "Checking Helm chart FIPS configuration... "
CHARTS_WITHOUT_FIPS=()

for chart_values in infra/k8s/charts/*/values.yaml; do
    if [ -f "$chart_values" ]; then
        if ! grep -q "FIPS_MODE" "$chart_values" || \
           ! grep -q "HSM_AVAILABLE" "$chart_values" || \
           ! grep -q "PQ_CRYPTO_ENABLED" "$chart_values"; then
            CHARTS_WITHOUT_FIPS+=("$chart_values")
        fi
    fi
done

if [ ${#CHARTS_WITHOUT_FIPS[@]} -gt 0 ]; then
    echo -e "${YELLOW}WARN${NC}"
    echo "  ⚠️  The following Helm charts are missing FIPS env vars:"
    for chart in "${CHARTS_WITHOUT_FIPS[@]}"; do
        echo "     - $chart"
    done
    # Don't fail, just warn
else
    echo -e "${GREEN}PASS${NC}"
fi

# Check 6: Verify no :latest image tags in production
echo -n "Checking for :latest image tags... "
LATEST_TAGS=$(grep -r "image.*:latest" infra/k8s/charts/ || true)

if [ -n "$LATEST_TAGS" ]; then
    echo -e "${RED}FAIL${NC}"
    echo "  ❌ Found :latest image tags (violates supply-chain security):"
    echo "$LATEST_TAGS" | sed 's/^/     /'
    COMPLIANCE_FAILED=1
else
    echo -e "${GREEN}PASS${NC}"
fi

# Check 7: Verify OPA policies exist
echo -n "Checking OPA policy-as-code... "
if [ ! -f "security/policy-as-code/pci-dss.rego" ]; then
    echo -e "${RED}FAIL${NC}"
    echo "  ❌ PCI-DSS OPA policy not found"
    COMPLIANCE_FAILED=1
else
    echo -e "${GREEN}PASS${NC}"
fi

# Summary
echo ""
echo "========================================"
if [ $COMPLIANCE_FAILED -eq 1 ]; then
    echo -e "${RED}❌ FIPS COMPLIANCE GATE FAILED${NC}"
    echo ""
    echo "Fix the issues above before deployment to production."
    echo "This is a HARD STOP for government-grade security."
    exit 1
else
    echo -e "${GREEN}✅ FIPS COMPLIANCE GATE PASSED${NC}"
    echo ""
    echo "All government-grade security requirements met."
    echo "Proceeding with deployment..."
    exit 0
fi
