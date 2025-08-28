# NACM Rust Prototype

A Rust implementation of **NACM** (Network Access Control Model) as defined in [RFC 8341](https://tools.ietf.org/rfc/rfc8341.txt), with support for **Tail-f ACM extensions** for command-based access control. This prototype demonstrates parsing real NACM XML configurations and validating access requests against defined rules.

## 🚀 Features

### Standard NACM (RFC 8341)
- **XML Configuration Parsing**: Parse real-world NACM XML configurations
- **Rule-based Access Control**: Support for permit/deny rules with precedence
- **Group Management**: User groups with inheritance
- **Operation Support**: Read, Create, Update, Delete, and Exec operations
- **Path Matching**: XPath-style path matching for fine-grained access control
- **RPC-level Control**: Control access to specific NETCONF RPCs
- **Module-based Rules**: Control access to specific YANG modules

### Tail-f ACM Extensions
- **Command Rules**: Access control for CLI and Web UI operations (`<cmdrule>`)
- **Enhanced Logging**: Fine-grained logging control with `log-if-permit`/`log-if-deny`
- **Context-Aware Rules**: Different rules for NETCONF, CLI, WebUI contexts
- **Group ID Mapping**: OS-level group integration with `<gid>` mapping
- **Command Default Policies**: Separate default policies for command operations
- **Symmetric Logging**: Control logging for both permit and deny decisions

## 📋 Prerequisites

- **Rust toolchain** (1.70 or later recommended)
- **Cargo** package manager

## 🔧 Building the Project

```bash
# Clone the repository
git clone <repository-url>
cd nacm-rust-prototype

# Build the project (library and CLI tool)
cargo build

# Build in release mode (optimized)
cargo build --release

# Build just the CLI tool
cargo build --bin nacm-validator

# Build just the library
cargo build --lib
```

## 🧪 Running Tests

The project includes comprehensive tests covering XML parsing and access validation:

```bash
# Run all tests
cargo test

# Run tests with detailed output
cargo test -- --nocapture

# Run a specific test
cargo test test_real_nacm_xml

# Run tests and show successful test output
cargo test -- --show-output
```

### Test Coverage

The tests include:
- ✅ XML parsing validation
- ✅ Basic rule matching
- ✅ Real-world NACM configuration parsing
- ✅ Access validation scenarios
- ✅ Group membership resolution

## 📖 Running Examples

### Access Validation Example

The main example demonstrates parsing a real NACM XML file and validating various access scenarios:

```bash
cargo run --example validate_access
```

This example shows:
- Loading NACM configuration from XML
- Validating different user access scenarios
- Demonstrating permit/deny decisions based on rules

### Tail-f ACM Extensions Demo

Run the comprehensive Tail-f ACM demo to see all the advanced features in action:

```bash
cargo run --example tailf_acm_demo
```

This demo showcases:
- Command rules with context awareness (CLI, WebUI, NETCONF)
- Enhanced logging configuration and validation
- Group ID (GID) mapping for external authentication
- ValidationResult with both access decision and logging information
- Context-specific access control policies

**Example Output:**
```
🔧 Tail-f ACM Configuration loaded:
- NACM enabled: true
- Default policies:
  * Data: read=Deny, write=Deny, exec=Deny
  * Commands: cmd_read=Deny, cmd_exec=Deny
- Logging: default_permit=true, default_deny=true
- Groups: ["operators", "admin"]
  * operators (GID: 1000): ["alice", "bob"]
  * admin (GID: 0): ["admin"]
- Rule lists: 2

🔍 Command access validation results:
  ✅ Alice (operator) - CLI show status: PERMIT 📝[LOG]
  ❌ Bob (operator) - CLI reboot: DENY 📝[LOG]
  ✅ Admin - WebUI config backup: PERMIT
...
```

**Example Output:**
```
NACM Configuration loaded:
- NACM enabled: true
- Default policies: read=Deny, write=Deny, exec=Deny
- Groups: ["oper", "admin"]
- Rule lists: 3

Access validation results:
- Admin executing edit-config: ✅ PERMIT
- Oper executing edit-config: ❌ DENY
- Oper modifying NACM config: ❌ DENY
- Guest reading example/misc/data: ✅ PERMIT
- Guest creating example/misc: ✅ PERMIT
- Unknown user reading data: ✅ PERMIT
```

## 📁 Project Structure

```
nacm-rust-prototype/
├── src/
│   ├── lib.rs                    # Main library implementation with Tail-f ACM extensions
│   └── bin/
│       └── nacm-validator.rs     # CLI tool for bash integration
├── examples/
│   ├── validate_access.rs        # Access validation example
│   ├── tailf_acm_demo.rs         # Tail-f ACM comprehensive demo
│   ├── bash_examples.sh          # Bash script integration examples
│   ├── json_batch_example.sh     # JSON batch processing examples
│   └── data/
│       ├── aaa_ncm_init.xml      # Real NACM configuration (insecure example)
│       ├── aaa_ncm_init_secure.xml # Secure NACM configuration
│       └── tailf_acm_example.xml # Tail-f ACM extension example
├── doc/
│   └── rfc-tailf-acm-proposal.md # Tail-f ACM RFC proposal document
├── Cargo.toml                    # Project configuration
└── README.md                     # This file
```

## ⚠️ Security Note

The original `aaa_ncm_init.xml` contains a security vulnerability - it has a catch-all rule that permits access for **any user** (including unknown users). This is dangerous:

```xml
<rule>
  <name>any-access</name>
  <action>permit</action>
</rule>
```

### Testing the Security Issue

```bash
# ❌ INSECURE: Unknown user 'bill' gets access with original config
./target/release/nacm-validator \
    --config examples/data/aaa_ncm_init.xml \
    --user bill \
    --operation exec \
    --rpc edit-config
# Output: PERMIT (this is wrong!)

# ✅ SECURE: Unknown user 'bill' denied with secure config
./target/release/nacm-validator \
    --config examples/data/aaa_ncm_init_secure.xml \
    --user bill \
    --operation exec \
    --rpc edit-config
# Output: DENY (this is correct!)
```

**Always use `aaa_ncm_init_secure.xml` for production-like testing.**

## 🛠️ Using as a Library

Add this to your `Cargo.toml`:

```toml
[dependencies]
nacm-rust-prototype = { path = "../nacm-rust-prototype" }
```

### Basic Library Usage

```rust
use nacm_rust_prototype::{AccessRequest, NacmConfig, Operation, RequestContext, ValidationResult};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load NACM configuration from XML
    let xml_content = std::fs::read_to_string("examples/data/aaa_ncm_init.xml")?;
    let config = NacmConfig::from_xml(&xml_content)?;
    
    // Create a data access request
    let context = RequestContext::NETCONF;
    let data_request = AccessRequest {
        user: "alice",
        module_name: Some("ietf-interfaces"),
        rpc_name: None,
        operation: Operation::Read,
        path: Some("/interfaces"),
        context: Some(&context),
        command: None,
    };
    
    // Validate the data request
    let result = config.validate(&data_request);
    println!("Data access {}: {}", 
             if result.effect == nacm_rust_prototype::RuleEffect::Permit { "PERMITTED" } else { "DENIED" },
             if result.should_log { "[LOGGED]" } else { "" });
    
    // Create a command access request (Tail-f extension)
    let cli_context = RequestContext::CLI;
    let command_request = AccessRequest {
        user: "alice",
        module_name: None,
        rpc_name: None,
        operation: Operation::Read,
        path: None,
        context: Some(&cli_context),
        command: Some("show interfaces"),
    };
    
    // Validate the command request
    let cmd_result = config.validate(&command_request);
    println!("Command access {}: {}", 
             if cmd_result.effect == nacm_rust_prototype::RuleEffect::Permit { "PERMITTED" } else { "DENIED" },
             if cmd_result.should_log { "[LOGGED]" } else { "" });
    
    Ok(())
}
```

The `validate()` method now returns a `ValidationResult` struct containing:
- `effect`: `RuleEffect::Permit` or `RuleEffect::Deny`
- `should_log`: Whether this decision should be logged based on the rule's logging configuration

### Quick CLI Usage

```bash
# Build the CLI tool
cargo build --bin nacm-validator

# Validate a simple request (using secure config)
cargo run --bin nacm-validator -- \
    --config examples/data/aaa_ncm_init_secure.xml \
    --user admin \
    --operation exec \
    --rpc edit-config
# Output: PERMIT (exit code 0)

# Test denied access
cargo run --bin nacm-validator -- \
    --config examples/data/aaa_ncm_init_secure.xml \
    --user oper \
    --operation exec \
    --rpc edit-config
# Output: DENY (exit code 1)

# Test unknown user (should be denied)
cargo run --bin nacm-validator -- \
    --config examples/data/aaa_ncm_init_secure.xml \
    --user unknown \
    --operation exec \
    --rpc edit-config  
# Output: DENY (exit code 1)
```

## 📚 API Documentation

Generate and view the complete API documentation:

```bash
cargo doc --open
```

This opens the documentation in your browser, showing all available types, traits, and functions.

## 🧩 Core Types

### Key Structures

- **`NacmConfig`**: Main configuration containing groups and rule lists
- **`NacmRule`**: Individual access control rule
- **`AccessRequest`**: Represents an access attempt
- **`RuleEffect`**: Permit or Deny decision
- **`Operation`**: CRUD + Exec operations

### Example Rule Structure

```rust
NacmRule {
    name: "allow-admin-read".to_string(),
    module_name: Some("ietf-interfaces".to_string()),
    rpc_name: None,
    path: Some("/interfaces/*".to_string()),
    access_operations: [Operation::Read].into(),
    effect: RuleEffect::Permit,
    order: 10,
}
```

## 🖥️ Command Line Interface

The project includes a powerful CLI tool for validating NACM access requests from bash scripts and automation.

### Building the CLI

```bash
# Build the CLI tool
cargo build --bin nacm-validator

# Build optimized version
cargo build --bin nacm-validator --release

# The binary will be available at:
# ./target/debug/nacm-validator (debug build)
# ./target/release/nacm-validator (release build)
```

### Basic Usage

```bash
# Using cargo run (recommended for development)
cargo run --bin nacm-validator -- \
    --config examples/data/aaa_ncm_init.xml \
    --user admin \
    --operation exec \
    --rpc edit-config

# Using the built binary directly
./target/release/nacm-validator \
    --config examples/data/aaa_ncm_init.xml \
    --user admin \
    --operation exec \
    --rpc edit-config

# Output: PERMIT (exit code 0) or DENY (exit code 1)
```

### CLI Options

```
Options:
  -c, --config <CONFIG>        Path to the NACM XML configuration file
  -u, --user <USER>            Username making the request
  -m, --module <MODULE>        Module name (optional)
  -r, --rpc <RPC>              RPC name (optional)
  -o, --operation <OPERATION>  Operation type [read, create, update, delete, exec]
  -p, --path <PATH>            Path (optional)
      --format <FORMAT>        Output format [text, json, exit-code]
  -v, --verbose                Verbose output
      --json-input             JSON input mode - read requests from stdin
```

### Bash Script Integration

#### Exit Code Based Validation
```bash
#!/bin/bash
CONFIG="examples/data/aaa_ncm_init.xml"

# Simple validation with exit codes using cargo run
if cargo run --bin nacm-validator -- --config "$CONFIG" --user admin --operation exec --rpc edit-config; then
    echo "Access granted"
else
    echo "Access denied"
fi

# Or using the built binary (faster for repeated calls)
VALIDATOR="./target/release/nacm-validator"
if $VALIDATOR --config "$CONFIG" --user admin --operation exec --rpc edit-config; then
    echo "Access granted"
else
    echo "Access denied"
fi
```

#### JSON Output Processing
```bash
# Get detailed results as JSON
JSON_OUTPUT=$(cargo run --bin nacm-validator -- \
    --config examples/data/aaa_ncm_init.xml \
    --user oper \
    --operation update \
    --module ietf-netconf-acm \
    --format json)

# Extract decision
DECISION=$(echo "$JSON_OUTPUT" | grep -o '"decision":"[^"]*"' | cut -d'"' -f4)
echo "Decision: $DECISION"
```

#### Batch Processing
```bash
# Process multiple requests from JSON file
cat requests.json | cargo run --bin nacm-validator -- \
    --config examples/data/aaa_ncm_init.xml \
    --json-input

# Example requests.json:
# {"user": "admin", "operation": "exec", "rpc": "edit-config"}
# {"user": "oper", "operation": "read", "module": "ietf-interfaces"}

# More examples:
echo '{"user": "admin", "operation": "exec", "rpc": "edit-config"}' | \
 ./target/release/nacm-validator --config examples/data/aaa_ncm_init_secure.xml --json-input
{"decision":"permit","user":"admin","module":null,"rpc":"edit-config","operation":"exec","path":null,"config_loaded":true}

echo '{"user": "alice", "operation": "exec", "rpc": "edit-config"}' | \
 ./target/release/nacm-validator --config examples/data/aaa_ncm_init_secure.xml --json-input
{"decision":"deny","user":"alice","module":null,"rpc":"edit-config","operation":"exec","path":null,"config_loaded":true}
```

### Example Scripts and Programs

The project includes comprehensive working examples:

```bash
# Run standard NACM access validation demo
cargo run --example validate_access

# Run comprehensive Tail-f ACM extensions demo
cargo run --example tailf_acm_demo

# Run bash integration examples
./examples/bash_examples.sh

# Run JSON batch processing example
./examples/json_batch_example.sh
```

These examples demonstrate:
- ✅ Standard NACM access validation with real configurations
- ✅ Tail-f ACM command rules with context awareness
- ✅ ValidationResult usage with logging information
- ✅ CLI integration with exit codes
- ✅ JSON output processing
- ✅ Batch request processing
- ✅ Error handling
- ✅ API integration simulation

## 🔍 Development

### Adding New Tests

Tests are located in `src/lib.rs` within the `#[cfg(test)]` module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_my_scenario() {
        // Your test here
    }
}
```

### Creating New Examples

Add new examples in the `examples/` directory:

```rust
// examples/my_example.rs
use nacm_rust_prototype::*;

fn main() {
    // Your example code
}
```

Run with: `cargo run --example my_example`

## 📄 License

This project is licensed under the Mozilla Public License 2.0 (MPL-2.0). See the [LICENSE](LICENSE) file for details.

This is a prototype implementation for educational and research purposes.

## 🤝 Contributing

This is a prototype project. Feel free to experiment and extend the functionality!

### Development Commands

```bash
# Format code
cargo fmt

# Run clippy for lints
cargo clippy

# Check without building
cargo check

# Clean build artifacts
cargo clean
```

## 📖 References

- [RFC 8341 - Network Configuration Access Control Model](https://tools.ietf.org/rfc/rfc8341.txt)
- [YANG Data Modeling Language](https://tools.ietf.org/rfc/rfc7950.txt)
- [NETCONF Protocol](https://tools.ietf.org/rfc/rfc6241.txt)
