#!/bin/bash

# JSON Batch Processing Example for NACM Validator - Updated for Tail-f ACM Extensions

echo "=== JSON Batch Processing Example with Tail-f ACM ==="

# Build the CLI tool
echo "Building NACM validator..."
cargo build --bin nacm-validator --release --quiet

NACM_VALIDATOR="./target/release/nacm-validator"
CONFIG_FILE="examples/data/tailf_acm_example.xml"
STANDARD_CONFIG="examples/data/aaa_ncm_init.xml"

# Create a JSON file with multiple requests including Tail-f ACM features
cat > /tmp/nacm_requests.json << 'EOF'
{"user": "admin", "operation": "exec", "rpc": "edit-config", "context": "netconf"}
{"user": "alice", "operation": "read", "context": "cli", "command": "show status"}
{"user": "bob", "operation": "read", "context": "cli", "command": "show interfaces"}
{"user": "alice", "operation": "read", "context": "webui", "command": "help"}
{"user": "charlie", "operation": "read", "context": "cli", "command": "show status"}
{"user": "admin", "operation": "exec", "context": "cli", "command": "reboot"}
{"user": "bob", "operation": "exec", "context": "cli", "command": "reboot"}
{"user": "alice", "operation": "read", "module": "ietf-interfaces", "path": "/interfaces", "context": "netconf"}
{"user": "alice", "operation": "exec", "rpc": "edit-config", "context": "netconf"}
{"user": "admin", "operation": "read", "module": "ietf-interfaces", "path": "/interfaces", "context": "netconf"}
{"user": "unknown", "operation": "read", "context": "cli", "command": "show status"}
EOF

echo "Processing batch requests with Tail-f ACM extensions..."
echo

# Process the JSON requests and show enhanced output
while IFS= read -r json_line; do
    result=$($NACM_VALIDATOR --config "$CONFIG_FILE" --json-input <<< "$json_line")
    
    # Extract fields for display
    user=$(echo "$result" | grep -o '"user":"[^"]*"' | cut -d'"' -f4)
    operation=$(echo "$result" | grep -o '"operation":"[^"]*"' | cut -d'"' -f4)
    decision=$(echo "$result" | grep -o '"decision":"[^"]*"' | cut -d'"' -f4)
    should_log=$(echo "$result" | grep -o '"should_log":[^,}]*' | cut -d':' -f2)
    context=$(echo "$result" | grep -o '"context":"[^"]*"' | cut -d'"' -f4)
    command=$(echo "$result" | grep -o '"command":"[^"]*"' | cut -d'"' -f4)
    module=$(echo "$result" | grep -o '"module":"[^"]*"' | cut -d'"' -f4)
    rpc=$(echo "$result" | grep -o '"rpc":"[^"]*"' | cut -d'"' -f4)
    
    # Format the output nicely
    if [ "$decision" = "permit" ]; then
        status="✅ PERMIT"
    else
        status="❌ DENY"
    fi
    
    # Add logging indicator
    if [ "$should_log" = "true" ]; then
        status="$status 📝"
    fi
    
    # Build description based on available fields
    desc="$user"
    if [ -n "$context" ] && [ "$context" != "null" ]; then
        desc="$desc ($context)"
    fi
    
    if [ -n "$command" ] && [ "$command" != "null" ]; then
        desc="$desc executing command '$command'"
    elif [ -n "$rpc" ] && [ "$rpc" != "null" ]; then
        desc="$desc executing RPC '$rpc'"
    elif [ -n "$module" ] && [ "$module" != "null" ]; then
        desc="$desc performing '$operation' on module '$module'"
    else
        desc="$desc performing '$operation'"
    fi
    
    echo "$status: $desc"
done < /tmp/nacm_requests.json

echo
echo "=== Enhanced Statistics with Tail-f ACM ==="

# Generate statistics
total_requests=$(wc -l < /tmp/nacm_requests.json)
results=$($NACM_VALIDATOR --config "$CONFIG_FILE" --json-input < /tmp/nacm_requests.json)
permits=$(echo "$results" | grep -c '"decision":"permit"')
denies=$(echo "$results" | grep -c '"decision":"deny"')
logged=$(echo "$results" | grep -c '"should_log":true')
command_requests=$(echo "$results" | grep -c '"command":"[^"]*"')
data_requests=$((total_requests - command_requests))
cli_requests=$(echo "$results" | grep -c '"context":"cli"')
netconf_requests=$(echo "$results" | grep -c '"context":"netconf"')
webui_requests=$(echo "$results" | grep -c '"context":"webui"')

echo "Total requests: $total_requests"
echo "Permits: $permits"
echo "Denies: $denies"
echo "Logged events: $logged"
echo "Command requests: $command_requests"
echo "Data requests: $data_requests"
echo "Context breakdown:"
echo "  - CLI: $cli_requests"
echo "  - NETCONF: $netconf_requests" 
echo "  - WebUI: $webui_requests"

echo
echo "=== Comparison with Standard NACM ==="

# Test same requests against standard NACM config (without Tail-f extensions)
echo "Testing standard NACM behavior (without command rules)..."
standard_results=$($NACM_VALIDATOR --config "$STANDARD_CONFIG" --json-input < /tmp/nacm_requests.json 2>/dev/null)
standard_permits=$(echo "$standard_results" | grep -c '"decision":"permit"' 2>/dev/null || echo "0")
standard_denies=$(echo "$standard_results" | grep -c '"decision":"deny"' 2>/dev/null || echo "0")

echo "Standard NACM results:"
echo "  - Permits: $standard_permits"
echo "  - Denies: $standard_denies"
echo "  - Note: Command requests may fail or use defaults in standard NACM"

# Cleanup
rm /tmp/nacm_requests.json

echo
echo "=== Batch processing completed ==="
echo "This example demonstrates:"
echo "- JSON batch processing with Tail-f ACM extensions"
echo "- Command-based access control in batch mode"
echo "- Context-aware processing"
echo "- Enhanced logging information"
echo "- Comparison between Tail-f ACM and standard NACM"
