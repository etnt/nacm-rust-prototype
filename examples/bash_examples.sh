#!/bin/bash

# NACM Validation Examples for Bash Scripts - Updated for Tail-f ACM Extensions

# Build the CLI tool first
echo "Building NACM validator..."
cargo build --bin nacm-validator --release

# Set the path to the binary
NACM_VALIDATOR="./target/release/nacm-validator"
CONFIG_FILE="examples/data/tailf_acm_example.xml"
STANDARD_CONFIG="examples/data/aaa_ncm_init.xml"

echo "=== Basic NACM Validation Examples ==="

# Example 1: Simple validation with exit code check
echo "1. Testing admin user executing edit-config:"
if $NACM_VALIDATOR --config "$STANDARD_CONFIG" --user admin --operation exec --rpc edit-config; then
    echo "   ✅ Access granted"
else
    echo "   ❌ Access denied"
fi

# Example 2: Testing with denied access
echo
echo "2. Testing oper user executing edit-config:"
if $NACM_VALIDATOR --config "$STANDARD_CONFIG" --user oper --operation exec --rpc edit-config; then
    echo "   ✅ Access granted"
else
    echo "   ❌ Access denied"
fi

echo
echo "=== Tail-f ACM Command-Based Access Control ==="

# Example 3: CLI command access control
echo "3. Testing CLI command access:"
echo "   Bob executing 'show status' via CLI:"
if $NACM_VALIDATOR --config "$CONFIG_FILE" --user bob --operation read --context cli --command "show status"; then
    echo "   ✅ Access granted (with logging indicator)"
else
    echo "   ❌ Access denied"
fi

echo "   Charlie executing 'show status' via CLI:"
if $NACM_VALIDATOR --config "$CONFIG_FILE" --user charlie --operation read --context cli --command "show status"; then
    echo "   ✅ Access granted"
else
    echo "   ❌ Access denied (not in operator group)"
fi

# Example 4: Different contexts
echo
echo "4. Testing different contexts:"
echo "   Alice via WebUI help command:"
$NACM_VALIDATOR --config "$CONFIG_FILE" --user alice --operation read --context webui --command "help" --format text
echo "   Alice via NETCONF data access:"
$NACM_VALIDATOR --config "$CONFIG_FILE" --user alice --operation read --context netconf --module "ietf-interfaces" --path "/interfaces" --format text

# Example 5: Using exit-code format for silent operation with context
echo
echo "5. Silent validation with context awareness:"
USER="bob"
OPERATION="exec"
COMMAND="reboot"
if $NACM_VALIDATOR --config "$CONFIG_FILE" --user "$USER" --operation "$OPERATION" --context cli --command "$COMMAND" --format exit-code; then
    echo "   User '$USER' can execute '$COMMAND' via CLI"
else
    echo "   User '$USER' cannot execute '$COMMAND' via CLI"
fi

# Example 6: Capturing JSON output with Tail-f ACM features
echo
echo "6. JSON output with Tail-f ACM extensions:"
JSON_OUTPUT=$($NACM_VALIDATOR --config "$CONFIG_FILE" --user "alice" --operation read --context cli --command "show interfaces" --format json)
DECISION=$(echo "$JSON_OUTPUT" | jq -r '.decision' 2>/dev/null || echo "$JSON_OUTPUT" | grep -o '"decision":"[^"]*"' | cut -d'"' -f4)
SHOULD_LOG=$(echo "$JSON_OUTPUT" | jq -r '.should_log' 2>/dev/null || echo "$JSON_OUTPUT" | grep -o '"should_log":[^,}]*' | cut -d':' -f2)
CONTEXT=$(echo "$JSON_OUTPUT" | jq -r '.context' 2>/dev/null || echo "$JSON_OUTPUT" | grep -o '"context":"[^"]*"' | cut -d'"' -f4)
echo "   Decision: $DECISION, Should log: $SHOULD_LOG, Context: $CONTEXT"

# Example 7: Batch validation function with context awareness
echo
echo "7. Context-aware batch validation function:"
validate_access_with_context() {
    local user="$1"
    local operation="$2"
    local context="$3"
    local command="$4"
    local module="$5"
    local path="$6"
    
    echo -n "   $user/$operation"
    if [ -n "$context" ]; then
        echo -n " ($context context)"
    fi
    if [ -n "$command" ]; then
        echo -n " command:'$command'"
    elif [ -n "$module" ]; then
        echo -n " on $module$path"
    fi
    echo -n ": "
    
    local args="--config $CONFIG_FILE --user $user --operation $operation --format exit-code"
    if [ -n "$context" ]; then
        args="$args --context $context"
    fi
    if [ -n "$command" ]; then
        args="$args --command $command"
    fi
    if [ -n "$module" ]; then
        args="$args --module $module"
    fi
    if [ -n "$path" ]; then
        args="$args --path $path"
    fi
    
    if eval $NACM_VALIDATOR $args 2>/dev/null; then
        echo "PERMIT"
    else
        echo "DENY"
    fi
}

# Test multiple scenarios with contexts and commands
validate_access_with_context "alice" "read" "cli" "show status" "" ""
validate_access_with_context "bob" "exec" "cli" "reboot" "" ""
validate_access_with_context "admin" "exec" "cli" "reboot" "" ""
validate_access_with_context "alice" "read" "netconf" "" "ietf-interfaces" "/interfaces"
validate_access_with_context "alice" "read" "webui" "help" "" ""

echo
echo "=== Advanced Usage Examples ==="

# Example 8: Configuration check with Tail-f ACM
echo "8. Tail-f ACM configuration summary:"
$NACM_VALIDATOR --config "$CONFIG_FILE" --user admin --operation read --verbose 2>&1 | head -6

# Example 9: Error handling
echo
echo "9. Error handling examples:"
echo "   Invalid context:"
if ! $NACM_VALIDATOR --config "$CONFIG_FILE" --user test --operation read --context invalid 2>/dev/null; then
    echo "   ✅ Handled invalid context gracefully"
fi

echo "   Missing config file:"
if ! $NACM_VALIDATOR --config "nonexistent.xml" --user test --operation read 2>/dev/null; then
    echo "   ✅ Handled missing config file gracefully"
fi

echo
echo "=== Integration Examples ==="

# Example 10: CLI command validation pipeline
echo "10. CLI command validation pipeline:"
simulate_cli_session() {
    local user="$1"
    echo "   Simulating CLI session for user: $user"
    
    local commands=("show status" "show interfaces" "help" "configure" "reboot")
    for cmd in "${commands[@]}"; do
        # Determine operation based on command
        local op="read"
        if [[ "$cmd" == "configure" || "$cmd" == "reboot" ]]; then
            op="exec"
        fi
        
        echo -n "     $cmd: "
        if $NACM_VALIDATOR --config "$CONFIG_FILE" --user "$user" --operation "$op" --context cli --command "$cmd" --format exit-code 2>/dev/null; then
            echo "✅ Allowed"
        else
            echo "❌ Blocked"
        fi
    done
}

simulate_cli_session "alice"
simulate_cli_session "charlie"

# Example 11: Web API integration with context awareness
echo
echo "11. Context-aware web API simulation:"
simulate_context_api_request() {
    local method="$1"  # GET, POST, PUT, DELETE
    local user="$2"
    local resource="$3"
    local context="$4" # netconf, webui
    
    # Map HTTP methods to NACM operations
    case "$method" in
        GET) operation="read" ;;
        POST) operation="create" ;;
        PUT) operation="update" ;;
        DELETE) operation="delete" ;;
        *) operation="read" ;;
    esac
    
    echo -n "   $method $resource as $user ($context): "
    if $NACM_VALIDATOR --config "$CONFIG_FILE" --user "$user" --operation "$operation" --context "$context" --path "$resource" --format exit-code 2>/dev/null; then
        echo "200 OK"
    else
        echo "403 Forbidden"
    fi
}

simulate_context_api_request "GET" "alice" "/interfaces" "netconf"
simulate_context_api_request "GET" "alice" "/interfaces" "webui"
simulate_context_api_request "DELETE" "admin" "/nacm/groups" "netconf"
simulate_context_api_request "POST" "bob" "/misc/new-item" "webui"

echo
echo "=== Script completed ==="
echo "This example demonstrates:"
echo "- Traditional NACM data access control"
echo "- Tail-f ACM command-based access control"
echo "- Context-aware rules (CLI, NETCONF, WebUI)"
echo "- Enhanced logging capabilities"
echo "- JSON output with extended information"
echo "- Error handling for invalid contexts"
