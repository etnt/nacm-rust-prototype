# nacm-rust-prototype
Experimental NACM implementation in Rust

This prototype implements basic NACM (Network Access Control Model, RFC 8341) rule validation in Rust. It provides structures for defining access control rules and validating access requests against those rules.

## Features

- Define NACM rules with permit/deny effects
- Rule matching based on user, module, operation, and path
- Rule precedence based on order (lower values have higher precedence)
- Basic access request validation against rule lists

## Building and Running

### Prerequisites
- Rust toolchain (cargo and rustc)

### Building the Project
```bash
cargo build
```

### Running Tests
The prototype includes unit tests that demonstrate the NACM validation functionality:

```bash
cargo test
```

To see test output with more detail:
```bash
cargo test -- --nocapture
```

### Using the Library
This is a library crate. You can use it in your own Rust projects by adding it as a dependency, or explore the API by running:

```bash
cargo doc --open
```

This will generate and open the documentation in your browser, showing the available types and functions for NACM rule validation.

## Example Usage

The prototype includes a basic example in the test code that shows how to:
1. Create NACM rules with specific users, modules, operations, and paths
2. Create access requests
3. Validate requests against rule lists

See `src/lib.rs` for the complete implementation and test examples.
