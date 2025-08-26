#!/bin/bash

# JSON Batch Processing Example for NACM Validator

echo "=== JSON Batch Processing Example ==="

# Build the CLI tool
echo "Building NACM validator..."
cargo build --bin nacm-validator --release --quiet

NACM_VALIDATOR="./target/release/nacm-validator"
CONFIG_FILE="examples/data/aaa_ncm_init.xml"

# Create a JSON file with multiple requests
cat > /tmp/nacm_requests.json << 'EOF'
{"user": "admin", "operation": "exec", "rpc": "edit-config"}
{"user": "oper", "operation": "exec", "rpc": "edit-config"}
{"user": "admin", "operation": "read", "module": "ietf-interfaces", "path": "/interfaces"}
{"user": "oper", "operation": "update", "module": "ietf-netconf-acm", "path": "/"}
{"user": "Guest", "operation": "read", "module": "example", "path": "/misc/data"}
{"user": "Guest", "operation": "create", "module": "example", "path": "/misc"}
{"user": "unknown", "operation": "read", "module": "test", "path": "/data"}
EOF

echo "Processing batch requests from JSON..."
echo

# Process the JSON requests
while IFS= read -r json_line; do
    result=$($NACM_VALIDATOR --config "$CONFIG_FILE" --json-input <<< "$json_line")
    
    # Extract fields for display
    user=$(echo "$result" | grep -o '"user":"[^"]*"' | cut -d'"' -f4)
    operation=$(echo "$result" | grep -o '"operation":"[^"]*"' | cut -d'"' -f4)
    decision=$(echo "$result" | grep -o '"decision":"[^"]*"' | cut -d'"' -f4)
    module=$(echo "$result" | grep -o '"module":"[^"]*"' | cut -d'"' -f4)
    rpc=$(echo "$result" | grep -o '"rpc":"[^"]*"' | cut -d'"' -f4)
    
    # Format the output nicely
    if [ "$decision" = "permit" ]; then
        status="✅ PERMIT"
    else
        status="❌ DENY"
    fi
    
    if [ -n "$rpc" ]; then
        echo "$status: $user executing RPC '$rpc'"
    elif [ -n "$module" ]; then
        echo "$status: $user performing '$operation' on module '$module'"
    else
        echo "$status: $user performing '$operation'"
    fi
done < /tmp/nacm_requests.json

echo
echo "=== Summary Statistics ==="

# Generate statistics
total_requests=$(wc -l < /tmp/nacm_requests.json)
permits=$($NACM_VALIDATOR --config "$CONFIG_FILE" --json-input < /tmp/nacm_requests.json | grep -c '"decision":"permit"')
denies=$($NACM_VALIDATOR --config "$CONFIG_FILE" --json-input < /tmp/nacm_requests.json | grep -c '"decision":"deny"')

echo "Total requests: $total_requests"
echo "Permits: $permits"
echo "Denies: $denies"

# Cleanup
rm /tmp/nacm_requests.json

echo
echo "=== Batch processing completed ==="
