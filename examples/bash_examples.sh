#!/bin/bash

# NACM Validation Examples for Bash Scripts

# Build the CLI tool first
echo "Building NACM validator..."
cargo build --bin nacm-validator --release

# Set the path to the binary
NACM_VALIDATOR="./target/release/nacm-validator"
CONFIG_FILE="examples/data/aaa_ncm_init.xml"

echo "=== Basic NACM Validation Examples ==="

# Example 1: Simple validation with exit code check
echo "1. Testing admin user executing edit-config:"
if $NACM_VALIDATOR --config "$CONFIG_FILE" --user admin --operation exec --rpc edit-config; then
    echo "   ✅ Access granted"
else
    echo "   ❌ Access denied"
fi

# Example 2: Testing with denied access
echo
echo "2. Testing oper user executing edit-config:"
if $NACM_VALIDATOR --config "$CONFIG_FILE" --user oper --operation exec --rpc edit-config; then
    echo "   ✅ Access granted"
else
    echo "   ❌ Access denied"
fi

# Example 3: Using exit-code format for silent operation
echo
echo "3. Silent validation (exit-code only):"
USER="admin"
OPERATION="read"
if $NACM_VALIDATOR --config "$CONFIG_FILE" --user "$USER" --operation "$OPERATION" --format exit-code --module "ietf-interfaces" --path "/interfaces"; then
    echo "   User '$USER' can perform '$OPERATION' operation"
else
    echo "   User '$USER' cannot perform '$OPERATION' operation"
fi

# Example 4: Capturing JSON output for processing
echo
echo "4. JSON output processing:"
JSON_OUTPUT=$($NACM_VALIDATOR --config "$CONFIG_FILE" --user "Guest" --operation read --module "example" --path "/misc/data" --format json)
DECISION=$(echo "$JSON_OUTPUT" | grep -o '"decision":"[^"]*"' | cut -d'"' -f4)
echo "   Decision for Guest accessing example data: $DECISION"

# Example 5: Batch validation function
echo
echo "5. Batch validation function:"
validate_access() {
    local user="$1"
    local operation="$2"
    local module="$3"
    local path="$4"
    
    echo -n "   $user/$operation on $module$path: "
    if $NACM_VALIDATOR --config "$CONFIG_FILE" --user "$user" --operation "$operation" --module "$module" --path "$path" --format exit-code 2>/dev/null; then
        echo "PERMIT"
    else
        echo "DENY"
    fi
}

# Test multiple scenarios
validate_access "admin" "read" "ietf-interfaces" "/interfaces"
validate_access "oper" "update" "ietf-netconf-acm" "/"
validate_access "Guest" "create" "example" "/misc"

echo
echo "=== Advanced Usage Examples ==="

# Example 6: Configuration check
echo "6. Configuration summary:"
$NACM_VALIDATOR --config "$CONFIG_FILE" --user admin --operation read --verbose 2>&1 | head -4

# Example 7: Error handling
echo
echo "7. Error handling example:"
if ! $NACM_VALIDATOR --config "nonexistent.xml" --user test --operation read 2>/dev/null; then
    echo "   Handled missing config file gracefully"
fi

echo
echo "=== Integration Examples ==="

# Example 8: Web API integration simulation
echo "8. Simulated API request validation:"
simulate_api_request() {
    local method="$1"  # GET, POST, PUT, DELETE
    local user="$2"
    local resource="$3"
    
    # Map HTTP methods to NACM operations
    case "$method" in
        GET) operation="read" ;;
        POST) operation="create" ;;
        PUT) operation="update" ;;
        DELETE) operation="delete" ;;
        *) operation="read" ;;
    esac
    
    echo -n "   $method $resource as $user: "
    if $NACM_VALIDATOR --config "$CONFIG_FILE" --user "$user" --operation "$operation" --path "$resource" --format exit-code 2>/dev/null; then
        echo "200 OK"
    else
        echo "403 Forbidden"
    fi
}

simulate_api_request "GET" "admin" "/interfaces"
simulate_api_request "DELETE" "oper" "/nacm/groups"
simulate_api_request "POST" "Guest" "/misc/new-item"

echo
echo "=== Script completed ==="
