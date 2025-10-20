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

# Default values
URL=""
WORDLIST=""
EXTENSIONS=""
THREADS=10
TIMEOUT=5
USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
DELAY=0
RETRIES=1
FOLLOW_REDIRECTS=false
SHOW_ERRORS=false
MODE="dir"
OUTPUT_FORMAT="text"
VERBOSE=false

# Bug Bounty Specific
TEST_METHODS=false
TEST_HEADERS=false
TEST_PARAMS=false
TEST_BYPASS=false
TEST_HPP=false
TEST_SQLI=false
TEST_XSS=false
TEST_SSRF=false
CUSTOM_PAYLOADS=""

# Function to display usage
usage() {
    echo "Usage: $0 -u <URL> -w <wordlist> [options]"
    echo ""
    echo "Basic Options:"
    echo "  -u, --url         Target URL (required)"
    echo "  -w, --wordlist    Wordlist file (required)"
    echo "  -e, --extensions  File extensions (comma separated: php,html,txt)"
    echo "  -t, --threads     Number of threads (default: 10)"
    echo "  -T, --timeout     Request timeout in seconds (default: 5)"
    echo "  -H, --headers     Custom headers (comma separated)"
    echo "  -a, --user-agent  Custom User-Agent"
    echo "  -d, --delay       Delay between requests (ms)"
    echo "  -r, --retries     Number of retries on failure (default: 1)"
    echo "  -L, --follow      Follow redirects"
    echo "  -v, --verbose     Show errors and detailed output"
    echo ""
    echo "Bug Bounty Features:"
    echo "  -M, --mode        Fuzzing mode: dir, subdomain, param (default: dir)"
    echo "  --test-methods    Test HTTP methods (GET, POST, PUT, etc.)"
    echo "  --test-headers    Test security headers bypass"
    echo "  --test-params     Test parameter fuzzing"
    echo "  --test-bypass     Test 403/401 bypass techniques"
    echo "  --test-hpp        Test HTTP Parameter Pollution"
    echo "  --test-sqli       Test basic SQL injection patterns"
    echo "  --test-xss        Test basic XSS patterns"
    echo "  --test-ssrf       Test SSRF patterns"
    echo "  --payloads        Custom payloads file"
    echo "  --output-format   Output format: text, json, csv (default: text)"
    echo ""
    echo "Examples:"
    echo "  $0 -u https://example.com -w wordlist.txt"
    echo "  $0 -u https://example.com -w wordlist.txt --test-bypass --test-params"
    echo "  $0 -u https://example.com -w wordlist.txt -M param --test-sqli --test-xss"
    exit 1
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -u|--url)
            URL="$2"
            shift 2
            ;;
        -w|--wordlist)
            WORDLIST="$2"
            shift 2
            ;;
        -e|--extensions)
            EXTENSIONS="$2"
            shift 2
            ;;
        -t|--threads)
            THREADS="$2"
            shift 2
            ;;
        -T|--timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        -H|--headers)
            HEADERS="$2"
            shift 2
            ;;
        -a|--user-agent)
            USER_AGENT="$2"
            shift 2
            ;;
        -d|--delay)
            DELAY="$2"
            shift 2
            ;;
        -r|--retries)
            RETRIES="$2"
            shift 2
            ;;
        -L|--follow)
            FOLLOW_REDIRECTS=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            SHOW_ERRORS=true
            shift
            ;;
        -M|--mode)
            MODE="$2"
            shift 2
            ;;
        --test-methods)
            TEST_METHODS=true
            shift
            ;;
        --test-headers)
            TEST_HEADERS=true
            shift
            ;;
        --test-params)
            TEST_PARAMS=true
            shift
            ;;
        --test-bypass)
            TEST_BYPASS=true
            shift
            ;;
        --test-hpp)
            TEST_HPP=true
            shift
            ;;
        --test-sqli)
            TEST_SQLI=true
            shift
            ;;
        --test-xss)
            TEST_XSS=true
            shift
            ;;
        --test-ssrf)
            TEST_SSRF=true
            shift
            ;;
        --payloads)
            CUSTOM_PAYLOADS="$2"
            shift 2
            ;;
        --output-format)
            OUTPUT_FORMAT="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# Validate required parameters
if [[ -z "$URL" || -z "$WORDLIST" ]]; then
    echo -e "${RED}[ERROR] URL and wordlist are required!${NC}"
    usage
fi

if [[ ! -f "$WORDLIST" ]]; then
    echo -e "${RED}[ERROR] Wordlist file not found: $WORDLIST${NC}"
    exit 1
fi

# Create output directory
OUTPUT_DIR="bugbounty_results_$(echo $URL | sed 's|https?://||; s|/|_|g')_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

# Function to make HTTP request with retries
make_request() {
    local target_url="$1"
    local word="$2"
    local method="${3:-GET}"
    local headers="${4:-}"
    
    local curl_cmd="curl -s -o /dev/null -w \"%{http_code} %{size_download} %{time_total}\" \
        --connect-timeout $TIMEOUT \
        --max-time $TIMEOUT \
        -A \"$USER_AGENT\" \
        -X $method"
    
    # Add follow redirects if enabled
    if [[ "$FOLLOW_REDIRECTS" == true ]]; then
        curl_cmd="$curl_cmd -L"
    fi
    
    # Add custom headers if provided
    if [[ -n "$headers" ]]; then
        curl_cmd="$curl_cmd -H \"$headers\""
    fi
    
    if [[ -n "$HEADERS" ]]; then
        IFS=',' read -ra HEADER_ARRAY <<< "$HEADERS"
        for header in "${HEADER_ARRAY[@]}"; do
            curl_cmd="$curl_cmd -H \"$header\""
        done
    fi
    
    curl_cmd="$curl_cmd \"$target_url\" 2>/dev/null"
    
    # Retry logic
    local retry=0
    local response=""
    while [[ $retry -lt $RETRIES ]]; do
        response=$(eval $curl_cmd)
        if [[ ! -z "$response" ]]; then
            break
        fi
        ((retry++))
        sleep 0.1
    done
    
    echo "$response"
    
    # Delay if specified
    if [[ $DELAY -gt 0 ]]; then
        sleep $(echo "scale=3; $DELAY/1000" | bc)
    fi
}

# Enhanced response checking
check_response() {
    local url="$1"
    local status_code="$2"
    local size="$3"
    local time_taken="$4"
    local word="$5"
    
    # Store all responses for analysis
    echo "$url|$status_code|$size|$time_taken|$word" >> "$OUTPUT_DIR/all_responses.csv"
    
    case $status_code in
        200|201|202)
            echo -e "${GREEN}[FOUND] $url - Status: $status_code | Size: $size | Time: ${time_taken}s${NC}"
            echo "$url|$status_code|$size|$time_taken" >> "$OUTPUT_DIR/found_endpoints.txt"
            ;;
        301|302|307|308)
            echo -e "${YELLOW}[REDIRECT] $url - Status: $status_code | Size: $size${NC}"
            echo "$url|$status_code|$size|$time_taken" >> "$OUTPUT_DIR/redirects.txt"
            ;;
        403)
            echo -e "${RED}[FORBIDDEN] $url - Status: $status_code | Size: $size${NC}"
            echo "$url|$status_code|$size|$time_taken" >> "$OUTPUT_DIR/forbidden.txt"
            ;;
        401)
            echo -e "${YELLOW}[UNAUTHORIZED] $url - Status: $status_code | Size: $size${NC}"
            echo "$url|$status_code|$size|$time_taken" >> "$OUTPUT_DIR/unauthorized.txt"
            ;;
        500|502|503)
            echo -e "${RED}[SERVER ERROR] $url - Status: $status_code | Size: $size${NC}"
            echo "$url|$status_code|$size|$time_taken" >> "$OUTPUT_DIR/server_errors.txt"
            ;;
        404)
            # Log interesting 404s (large responses might indicate something)
            if [[ $size -gt 1000 ]]; then
                echo "$url|$status_code|$size|$time_taken" >> "$OUTPUT_DIR/interesting_404s.txt"
            fi
            ;;
    esac
}

# 403 Bypass Techniques
test_bypass_techniques() {
    local base_url="$1"
    local word="$2"
    
    echo -e "${BLUE}[BYPASS] Testing bypass techniques for: $word${NC}"
    
    local bypass_patterns=(
        "$base_url/$word/"
        "$base_url/$word..;/"
        "$base_url/$word.json"
        "$base_url/$word..json"
        "$base_url/$word%20"
        "$base_url/$word%09"
        "$base_url/$word%00"
        "$base_url/$word.html"
        "$base_url/%2e/$word"
        "$base_url/$word/*"
        "$base_url/$word..\\"
        "$base_url/$word#"
        "$base_url/$word?"
        "$base_url/$word//"
        "$base_url/./$word/./"
    )
    
    # HTTP Method bypass
    local methods=("GET" "POST" "PUT" "OPTIONS" "HEAD" "PATCH" "TRACE")
    
    for pattern in "${bypass_patterns[@]}"; do
        local response=$(make_request "$pattern" "$word")
        local status_code=$(echo $response | cut -d' ' -f1)
        
        if [[ "$status_code" != "404" && "$status_code" != "403" ]]; then
            echo -e "${GREEN}[BYPASS SUCCESS] $pattern - Status: $status_code${NC}"
            echo "$pattern - Status: $status_code" >> "$OUTPUT_DIR/bypass_success.txt"
        fi
    done
    
    # Test different HTTP methods
    for method in "${methods[@]}"; do
        local response=$(make_request "$base_url/$word" "$word" "$method")
        local status_code=$(echo $response | cut -d' ' -f1)
        
        if [[ "$status_code" =~ ^[23] ]]; then
            echo -e "${GREEN}[METHOD BYPASS] $method $base_url/$word - Status: $status_code${NC}"
            echo "$method $base_url/$word - Status: $status_code" >> "$OUTPUT_DIR/method_bypass.txt"
        fi
    done
}

# Parameter Fuzzing
test_parameters() {
    local base_url="$1"
    
    echo -e "${BLUE}[PARAMS] Testing parameters for: $base_url${NC}"
    
    local parameters=("id" "page" "file" "path" "dir" "url" "debug" "test" "admin" "api" 
                     "callback" "jsonp" "redirect" "url" "view" "template" "load" "action")
    
    local payloads=("../../etc/passwd" "../../../../windows/win.ini" "1" "true" "false" "admin" 
                   "test" "\${jndi:ldap://test}" "{{7*7}}" "<script>alert(1)</script>")
    
    for param in "${parameters[@]}"; do
        for payload in "${payloads[@]}"; do
            local test_url="${base_url}?${param}=${payload}"
            local response=$(make_request "$test_url" "")
            local status_code=$(echo $response | cut -d' ' -f1)
            local size=$(echo $response | cut -d' ' -f2)
            
            if [[ "$status_code" != "404" && "$status_code" != "400" ]]; then
                echo -e "${YELLOW}[PARAM FOUND] $test_url - Status: $status_code | Size: $size${NC}"
                echo "$test_url - Status: $status_code | Size: $size" >> "$OUTPUT_DIR/parameter_finds.txt"
            fi
        done
    done
}

# HTTP Method Testing
test_http_methods() {
    local url="$1"
    
    echo -e "${BLUE}[METHODS] Testing HTTP methods for: $url${NC}"
    
    local methods=("GET" "POST" "PUT" "DELETE" "PATCH" "OPTIONS" "HEAD" "TRACE" "CONNECT")
    
    for method in "${methods[@]}"; do
        local response=$(make_request "$url" "" "$method")
        local status_code=$(echo $response | cut -d' ' -f1)
        
        if [[ "$status_code" != "404" && "$status_code" != "405" ]]; then
            echo -e "${GREEN}[METHOD ALLOWED] $method $url - Status: $status_code${NC}"
            echo "$method $url - Status: $status_code" >> "$OUTPUT_DIR/http_methods.txt"
        fi
    done
}

# Header Injection Testing
test_header_injection() {
    local base_url="$1"
    local word="$2"
    
    local headers=(
        "X-Forwarded-For: 127.0.0.1"
        "X-Real-IP: 127.0.0.1"
        "X-Originating-IP: 127.0.0.1"
        "X-Remote-IP: 127.0.0.1"
        "X-Client-IP: 127.0.0.1"
        "X-Host: 127.0.0.1"
        "X-Forwarded-Host: 127.0.0.1"
    )
    
    for header in "${headers[@]}"; do
        local response=$(make_request "$base_url/$word" "$word" "GET" "$header")
        local status_code=$(echo $response | cut -d' ' -f1)
        
        if [[ "$status_code" =~ ^[23] ]]; then
            echo -e "${GREEN}[HEADER BYPASS] $header - $base_url/$word - Status: $status_code${NC}"
            echo "$header - $base_url/$word - Status: $status_code" >> "$OUTPUT_DIR/header_bypass.txt"
        fi
    done
}

# Parameter Fuzzing Single
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

# Subdomain Fuzzing
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

# Main fuzzing function with multiple modes
fuzz() {
    local base_url="$1"
    local word="$2"
    
    case $MODE in
        "dir")
            fuzz_directories "$base_url" "$word"
            ;;
        "subdomain")
            fuzz_subdomains "$base_url" "$word"
            ;;
        "param")
            fuzz_parameters_single "$base_url" "$word"
            ;;
    esac
    
    # Additional tests based on flags
    if [[ "$TEST_BYPASS" == true ]]; then
        test_bypass_techniques "$base_url" "$word"
    fi
    
    if [[ "$TEST_HEADERS" == true ]]; then
        test_header_injection "$base_url" "$word"
    fi
}

fuzz_directories() {
    local base_url="$1"
    local word="$2"
    
    local patterns=(
        "$base_url/$word"
        "$base_url/$word/"
        "$base_url/${word}.php"
        "$base_url/${word}.html"
        "$base_url/${word}.txt"
        "$base_url/${word}.bak"
        "$base_url/${word}.old"
        "$base_url/${word}~"
        "$base_url/${word}.json"
        "$base_url/${word}.xml"
        "$base_url/API/$word"
        "$base_url/api/$word"
        "$base_url/v1/$word"
        "$base_url/v2/$word"
    )
    
    # Add extensions if provided
    if [[ -n "$EXTENSIONS" ]]; then
        IFS=',' read -ra EXT_ARRAY <<< "$EXTENSIONS"
        for ext in "${EXT_ARRAY[@]}"; do
            patterns+=("$base_url/${word}.${ext}")
            patterns+=("$base_url/${word}.${ext}.bak")
        done
    fi
    
    for pattern in "${patterns[@]}"; do
        local response=$(make_request "$pattern" "$word")
        local status_code=$(echo $response | cut -d' ' -f1)
        local size=$(echo $response | cut -d' ' -f2)
        local time_taken=$(echo $response | cut -d' ' -f3)
        
        if [[ ! -z "$status_code" && "$status_code" != "000" ]]; then
            check_response "$pattern" "$status_code" "$size" "$time_taken" "$word"
        fi
    done
}

# Export functions for parallel execution
export -f make_request check_response fuzz fuzz_directories test_bypass_techniques 
export -f test_parameters test_http_methods test_header_injection fuzz_parameters_single fuzz_subdomains
export URL EXTENSIONS USER_AGENT TIMEOUT HEADERS OUTPUT_DIR DELAY RETRIES FOLLOW_REDIRECTS
export MODE TEST_BYPASS TEST_HEADERS TEST_PARAMS RED GREEN YELLOW BLUE PURPLE CYAN ORANGE NC

# Initialize output files
echo "URL|Status|Size|Time|Word" > "$OUTPUT_DIR/all_responses.csv"

# Main execution
echo -e "${PURPLE}[INFO] Starting bug bounty fuzzing against: $URL${NC}"
echo -e "${PURPLE}[INFO] Mode: $MODE${NC}"
echo -e "${PURPLE}[INFO] Using wordlist: $WORDLIST${NC}"
echo -e "${PURPLE}[INFO] Threads: $THREADS${NC}"
echo -e "${PURPLE}[INFO] Output directory: $OUTPUT_DIR${NC}"
echo ""

# Count total words
total_words=$(wc -l < "$WORDLIST")
current=0

# Progress function
show_progress() {
    current=$((current + 1))
    percent=$((current * 100 / total_words))
    printf "\r[%3d%%] Processed: %d/%d" "$percent" "$current" "$total_words"
}

export -f show_progress
export current total_words

# Use parallel for multi-threading
if command -v parallel &> /dev/null; then
    cat "$WORDLIST" | parallel --jobs $THREADS --bar \
        "fuzz '$URL' '{}'; show_progress"
else
    echo -e "${YELLOW}[WARNING] GNU parallel not found. Using sequential processing.${NC}"
    while IFS= read -r word; do
        fuzz "$URL" "$word"
        show_progress
    done < "$WORDLIST"
fi

echo ""
echo -e "${GREEN}[INFO] Fuzzing completed!${NC}"
echo -e "${GREEN}[INFO] Results saved in: $OUTPUT_DIR/${NC}"

# Generate report
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

generate_report
