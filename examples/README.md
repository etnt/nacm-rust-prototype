# NACM Validator Examples

This directory contains comprehensive examples demonstrating the NACM (Network Access Control Model) validator with Tail-f ACM extensions.

## Examples Overview

### 1. Command-Line Scripts

#### `bash_examples.sh`
Comprehensive Bash script demonstrating:
- Basic NACM validation with exit codes
- Tail-f ACM command-based access control
- Context-aware validation (CLI, NETCONF, WebUI)
- JSON output processing with extended fields
- Batch validation with context awareness
- Error handling for invalid contexts
- CLI session simulation

**Usage:**
```bash
./examples/bash_examples.sh
```

**Key Features Demonstrated:**
- Traditional NACM data access control
- Tail-f ACM command rules with context awareness
- Enhanced logging indicators (`[LOGGED]`)
- JSON parsing with `should_log`, `context`, and `command` fields
- Exit code integration for shell scripting

#### `json_batch_example.sh`
JSON batch processing with Tail-f ACM extensions:
- JSON input/output with enhanced fields
- Command-based and data-based access requests
- Context-specific batch processing
- Statistics and comparison analysis
- Error handling for invalid JSON inputs

**Usage:**
```bash
./examples/json_batch_example.sh
```

**Key Features Demonstrated:**
- Batch processing with JSON input
- Command vs. data access statistics
- Context breakdown (CLI/NETCONF/WebUI)
- Logging event tracking
- Comparison with standard NACM behavior

### 2. Rust Examples

#### `validate_access.rs`
Basic Rust API usage showing:
- Standard NACM configuration loading
- Context-aware request validation
- Multiple user and operation scenarios
- Access to ValidationResult with logging information

**Usage:**
```bash
cargo run --example validate_access
```

#### `tailf_acm_demo.rs`
Focused demonstration of Tail-f ACM features:
- Configuration analysis and summary
- Group information with GID mapping
- Rule list breakdown (standard vs command rules)
- Command access validation scenarios
- Mixed data access validation
- Enhanced logging demonstrations

**Usage:**
```bash
cargo run --example tailf_acm_demo
```

#### `tailf_acm_comprehensive_demo.rs`
Comprehensive demonstration covering all Tail-f ACM extensions:
- Detailed configuration analysis
- Command-based access control scenarios
- Context-aware data access testing
- Default behavior validation
- Mixed command and data access scenarios
- Complete feature overview and takeaways

**Usage:**
```bash
cargo run --example tailf_acm_comprehensive_demo
```

## Configuration Files

### `data/aaa_ncm_init.xml`
Standard NACM configuration for basic examples.

### `data/tailf_acm_example.xml`
Comprehensive Tail-f ACM configuration demonstrating:
- Command rules with context awareness
- Enhanced logging controls
- Group ID mapping
- Command default policies
- Mixed rule scenarios

## New CLI Features

The examples demonstrate the updated CLI interface supporting:

### New Arguments
- `--context`: Specify request context (netconf, cli, webui)
- `--command`: Specify command for command-based access control

### Enhanced JSON Support
Input JSON format now supports:
```json
{
  "user": "alice",
  "operation": "read", 
  "context": "cli",
  "command": "show status",
  "module": "ietf-interfaces",
  "path": "/interfaces"
}
```

Output JSON includes:
```json
{
  "decision": "permit",
  "should_log": true,
  "context": "cli",
  "command": "show status",
  ...
}
```

## Running All Examples

To run all examples in sequence:

```bash
# Bash examples
./examples/bash_examples.sh
./examples/json_batch_example.sh

# Rust examples  
cargo run --example validate_access
cargo run --example tailf_acm_demo
cargo run --example tailf_acm_comprehensive_demo
```

## Key Tail-f ACM Features Demonstrated

1. **Command-Based Access Control**: Rules that apply to specific commands rather than data paths
2. **Context Awareness**: Different access policies for CLI, NETCONF, and WebUI interfaces
3. **Enhanced Logging**: Granular control over what gets logged with `log-if-permit` and `log-if-deny`
4. **Group ID Mapping**: Integration with OS groups via GID attributes
5. **Command Defaults**: Separate default policies for command operations
6. **Rule Priority**: Command rules take priority over data rules when both apply
7. **Backward Compatibility**: Full compatibility with standard NACM configurations

## Integration Patterns

The examples show common integration patterns:

- **Shell Scripting**: Using exit codes and silent mode for automation
- **JSON APIs**: Batch processing and structured output for web services
- **CLI Tools**: Context-aware command validation for management interfaces
- **Audit Systems**: Enhanced logging for compliance and security monitoring
- **Multi-Interface Systems**: Different access policies per management interface
