#!/bin/bash

# Web Fuzzer For Bug Bounty Hunter's, Penetration Tester, Security Researcher's
# Author: Md Nawshad Ahmmed
# GitHub: https://github.com/Nawshad-Ahmmed/web-fuzzer
# License: MIT
# Usage: Educational and authorized security testing only

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
ORANGE='\033[0;33m'
NC='\033[0m' # No Color

# Banner
echo -e "${PURPLE}"
echo "░█▄░█░█░▄▀▀░▀█▀░█▀▄░█▀▀░█▀▄"
echo "░█░█░█░█░░░░█░░█░█░█▀▀░█▀▄"
echo "░▀░▀░▀░▀▀▀░░▀░░▀▀░░▀▀▀░▀░▀"
echo -e "${CYAN}"
echo "Web Fuzzer v2.0 - Bug Bounty Edition"
echo "============================================="
echo -e "${NC}"

# [REST OF YOUR SCRIPT REMAINS THE SAME UNTIL THE BYPASS FUNCTION]

# 403 Bypass Techniques
test_bypass_techniques() {
    local base_url="$1"
    local word="$2"
    
    echo -e "${BLUE}[BYPASS] Testing bypass techniques for: $word${NC}"  # Fixed typo: BYAPSS -> BYPASS
    
    # [REST OF THIS FUNCTION REMAINS THE SAME]
}

# [ADD THIS MISSING FUNCTION]
fuzz_parameters_single() {
    local base_url="$1"
    local word="$2"
    
    echo -e "${BLUE}[PARAMS] Testing parameter: $word${NC}"
    
    local test_url="${base_url}?${word}=test"
    local response=$(make_request "$test_url" "$word")
    local status_code=$(echo $response | cut -d' ' -f1)
    local size=$(echo $response | cut -d' ' -f2)
    local time_taken=$(echo $response | cut -d' ' -f3)
    
    if [[ ! -z "$status_code" && "$status_code" != "000" && "$status_code" != "404" ]]; then
        check_response "$test_url" "$status_code" "$size" "$time_taken" "$word"
    fi
}

# [ADD THIS MISSING FUNCTION]
fuzz_subdomains() {
    local base_url="$1"
    local word="$2"
    
    # Extract domain from URL
    local domain=$(echo "$base_url" | sed -E 's|https?://([^/]+).*|\1|')
    local subdomain_url="https://${word}.${domain}"
    
    local response=$(make_request "$subdomain_url" "$word")
    local status_code=$(echo $response | cut -d' ' -f1)
    local size=$(echo $response | cut -d' ' -f2)
    local time_taken=$(echo $response | cut -d' ' -f3)
    
    if [[ ! -z "$status_code" && "$status_code" != "000" ]]; then
        check_response "$subdomain_url" "$status_code" "$size" "$time_taken" "$word"
    fi
}

# [REST OF YOUR SCRIPT REMAINS THE SAME UNTIL THE END]

# Generate report - FIX THE SYNTAX ERROR HERE
generate_report() {
    echo -e "${CYAN}"
    echo "=== BUG BOUNTY FUZZING REPORT ==="
    echo "Target: $URL"
    echo "Date: $(date)"
    echo "Wordlist: $WORDLIST"
    echo "================================"
    echo -e "${NC}"
    
    if [[ -f "$OUTPUT_DIR/found_endpoints.txt" ]]; then
        found_count=$(wc -l < "$OUTPUT_DIR/found_endpoints.txt")
        echo -e "${GREEN}[+] Found endpoints: $found_count${NC}"
    fi
    
    if [[ -f "$OUTPUT_DIR/bypass_success.txt" ]]; then
        bypass_count=$(wc -l < "$OUTPUT_DIR/bypass_success.txt")
        echo -e "${GREEN}[+] Bypass techniques successful: $bypass_count${NC}"
    fi
    
    if [[ -f "$OUTPUT_DIR/interesting_404s.txt" ]]; then
        interesting_count=$(wc -l < "$OUTPUT_DIR/interesting_404s.txt")
        echo -e "${YELLOW}[+] Interesting 404 responses: $interesting_count${NC}"
    fi
    
    if [[ -f "$OUTPUT_DIR/parameter_finds.txt" ]]; then
        param_count=$(wc -l < "$OUTPUT_DIR/parameter_finds.txt")
        echo -e "${YELLOW}[+] Parameter finds: $param_count${NC}"
    fi
    
    if [[ -f "$OUTPUT_DIR/redirects.txt" ]]; then
        redirect_count=$(wc -l < "$OUTPUT_DIR/redirects.txt")
        echo -e "${BLUE}[+] Redirects found: $redirect_count${NC}"
    fi
}

# Call the report function (remove the extra parenthesis)
generate_report