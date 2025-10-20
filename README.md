# web-fuzzer
A powerful, multi-threaded web fuzzing tool written in Bash for bug bounty hunters, penetration testers, and security researchers. Discover hidden endpoints, directories, and vulnerabilities with bypass techniques.

# ✨ Features:
🚀 Multi-threaded scanning with configurable threads

🎯 Multiple fuzzing modes (directories, subdomains, parameters)

🛡️ Bug Bounty Focused with 403/401 bypass techniques

🔧 Customizable headers, user agents, and payloads

📊 Comprehensive output with response analysis

⚡ Performance optimized with progress tracking

🎨 Color-coded results for easy analysis

📈 CSV export for further processing

🔍 Advanced testing (HTTP methods, header injection, parameter fuzzing)

# 📋 Table of Contents
• Installation

• Requirements

• Quick Start

• Usage

• Examples

• Output

• Contributing

• Legal Disclaimer

• License

# 🛠️ Installation
# Prerequisites: 
• Linux (Ubuntu, Debian, CentOS, Kali Linux) or macOS

• Bash 4.0 or higher

• curl - for HTTP requests

• GNU parallel (recommended) - for multi-threading

# Quick Installation:
# Clone the repository
git clone https://github.com/Nawshad-Ahmmed/web-fuzzer.git

# change directory
cd web-fuzzer

# Make the script executable
chmod +x web_fuzzer.sh

# Install dependencies (Ubuntu/Debian)
sudo apt update && sudo apt install parallel curl

# Install dependencies (CentOS/RHEL)
sudo yum install parallel curl

# Install dependencies (macOS)
brew install parallel curl

# 📋 Requirements
# Tools Required 
curl - sudo apt install curl

parallel - sudo apt install parallel

# Verify Installation
Check if all dependencies are installed

./web_fuzzer.sh --help

Expected output: Shows usage information and options

# 🚀 Quick Start

# Basic Directory Fuzzing:
./web_fuzzer.sh -u https://example.com -w wordlists/common_endpoints.txt

# Advanced Bug Bounty Scan:
./web_fuzzer.sh -u https://target.com -w wordlists/common_endpoints.txt --test-bypass --test-headers --test-params -t 20 -v

# 📖 Usage
# Basic Syntax: 
./web_fuzzer.sh -u <URL> -w <WORDLIST> [OPTIONS]

# Required Parameters:
• -u, --url - Target URL to fuzz

• -w, --wordlist - Path to wordlist file

# ⚖️ Legal Disclaimer

This tool is designed for authorized testing only. Use it only on targets you have explicit permission to test. The author is not responsible for any misuse or damage caused.




