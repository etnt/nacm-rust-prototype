# Project Plan: nacm-validator

## Goal
Provide both:
- A **library crate** (`nacm-validator`) that exposes reusable functionality.
- A **binary crate** (`nacm-validator-bin`) that installs a CLI tool named `nacm-validator`.

This ensures:
- Clean separation of concerns.
- No namespace/documentation collisions.
- A nice user experience (`cargo install nacm-validator-bin` → `nacm-validator` on the command line).


## Repository Layout

```
nacm-validator/ # workspace root
├── Cargo.toml # workspace definition
├── nacm-validator-lib/ # library crate
│ ├── Cargo.toml
│ └── src/lib.rs
└── nacm-validator-bin/ # binary crate
├── Cargo.toml
└── src/main.rs
```

## Workspace Root (`Cargo.toml`)

```toml
[workspace]
members = [
    "nacm-validator-lib",
    "nacm-validator-bin",
]
```

### Library Crate (nacm-validator-lib/Cargo.toml)

 ```toml
[package]
name = "nacm-validator"     # published crate name
version = "0.1.0"
edition = "2021"

[lib]
name = "nacm_validator"     # Rust import path (underscores required)
```

Published to crates.io as nacm-validator.

Rust users depend on it with:

 ```toml
[dependencies]
nacm-validator = "0.1"
```

And import it as:

```rust
use nacm_validator::SomeType;
```

### Binary Crate (nacm-validator-bin/Cargo.toml)

```toml
[package]
name = "nacm-validator-bin"   # published crate name
version = "0.1.0"
edition = "2021"

[dependencies]
nacm-validator = { path = "../nacm-validator-lib", version = "0.1" }

[[bin]]
name = "nacm-validator"       # actual installed binary name
path = "src/main.rs"
```

Published to crates.io as nacm-validator-bin.

Users install with:

```sh
cargo install nacm-validator-bin
nacm-validator --help
```

Publishing Workflow

Bump versions in both crates as needed.

Publish the library crate first:

```sh
cd nacm-validator-lib
cargo publish
```

Then publish the binary crate (after the library version is available on crates.io):

```sh
cd ../nacm-validator-bin
cargo publish
```

Benefits of this Setup

No collisions:

Library crate (nacm-validator) and binary crate (nacm-validator-bin) have distinct crates.io names.

Good docs:

API docs hosted at https://docs.rs/nacm-validator.

Binary crate won’t clutter docs since it’s just a CLI entry point.

Nice UX:

Users run nacm-validator on the command line without suffixes.
