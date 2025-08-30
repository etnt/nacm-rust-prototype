# Multiple Config Files Support - Implementation Plan

## Overview

This document outlines the implementation plan for adding multiple config file support to the nacm-validator through a new `--config-dir` option. This will allow loading and merging NACM configurations from multiple XML files in a directory.

## 1. User Interface Changes

### New Command-Line Option
- Add `--config-dir <DIR>` option to complement existing `--config <FILE>`
- Both options are mutually exclusive (validate this at startup)
- When `--config-dir` is used, scan directory for `.xml` files
- Process files in alphabetical order (deterministic behavior)

### Updated Help Text
```
USAGE:
    nacm-validator [OPTIONS] --config <FILE> | --config-dir <DIR>

OPTIONS:
    -c, --config <FILE>         Path to the NACM XML configuration file
        --config-dir <DIR>      Path to directory containing NACM XML files
    -u, --user <USER>           Username making the request
    ...
```

## 2. File Discovery and Processing

### Directory Scanning
- Scan specified directory for files with `.xml` extension
- Skip subdirectories (non-recursive scanning for safety)
- Sort filenames alphabetically for predictable merge order
- Log discovered files in verbose mode
- Handle empty directories gracefully (warn but continue)

### File Filtering
- Only process files ending in `.xml` (case-insensitive)
- Skip hidden files (starting with '.')
- Skip backup files (ending with '~', '.bak', '.orig')
- Skip temporary files (starting with '.tmp')

### Error Handling
- If directory doesn't exist: fatal error (exit code 2)
- If directory is empty: warning but continue with defaults
- If some files fail to parse: report errors but continue with valid files
- If ALL files fail to parse: fatal error (exit code 2)

## 3. Configuration Merging Strategy

### YANG/NACM Merge Semantics
Following standard YANG merge behavior:

#### Additive Elements (Lists)
- **Groups**: Merge all groups from all files
  - If same group name appears in multiple files, merge user lists
  - Later files can add users to existing groups
  - Conflicting GID values: last file wins (with warning)

- **Rule Lists**: Merge all rule lists from all files
  - If same rule list name appears multiple times: merge rules
  - Rules maintain their relative order within each file
  - Global rule ordering: file order determines precedence base

- **Rules**: All rules from all files are included
  - Each rule gets assigned a global order: `file_index * 10000 + rule_index`
  - This ensures rules from earlier files have higher precedence
  - Rules within same file maintain their original relative order

#### Overwrite Elements (Leaves)
- **Global Settings**: Last file wins for conflicting values
  - `enable-nacm`: boolean - last value wins
  - `read-default`, `write-default`, `exec-default`: last values win
  - Tail-f extensions (`cmd-*-default`, `log-if-*`): last values win

### Merge Implementation
```rust
pub fn merge_configs(configs: Vec<NacmConfig>) -> NacmConfig {
    let mut merged = NacmConfig::default();
    
    for (file_idx, config) in configs.into_iter().enumerate() {
        // Overwrite leaf values
        merged.enable_nacm = config.enable_nacm;
        merged.read_default = config.read_default;
        // ... other defaults
        
        // Merge groups
        for (name, group) in config.groups {
            merge_group(&mut merged.groups, name, group);
        }
        
        // Merge rule lists with adjusted ordering
        for mut rule_list in config.rule_lists {
            adjust_rule_order(&mut rule_list, file_idx);
            merge_rule_list(&mut merged.rule_lists, rule_list);
        }
    }
    
    merged
}
```

## 4. Implementation Details

### Code Changes Required

#### 1. CLI Structure Updates (`main.rs`)
```rust
#[derive(Parser)]
struct Cli {
    /// Path to the NACM XML configuration file
    #[arg(short, long, conflicts_with = "config_dir")]
    config: Option<PathBuf>,
    
    /// Path to directory containing NACM XML configuration files
    #[arg(long, conflicts_with = "config")]
    config_dir: Option<PathBuf>,
    
    // ... other fields unchanged
}
```

#### 2. New Configuration Loading Function
```rust
fn load_configs(cli: &Cli) -> Result<NacmConfig, Box<dyn std::error::Error>> {
    if let Some(config_file) = &cli.config {
        // Single file mode (existing behavior)
        load_single_config(config_file)
    } else if let Some(config_dir) = &cli.config_dir {
        // Multi-file mode (new behavior)
        load_directory_configs(config_dir, cli.verbose)
    } else {
        Err("Either --config or --config-dir must be specified".into())
    }
}

fn load_directory_configs(dir: &PathBuf, verbose: bool) -> Result<NacmConfig, Box<dyn std::error::Error>> {
    let xml_files = discover_xml_files(dir)?;
    
    if xml_files.is_empty() {
        eprintln!("Warning: No XML files found in directory {:?}", dir);
        return Ok(NacmConfig::default());
    }
    
    if verbose {
        eprintln!("Found {} XML files:", xml_files.len());
        for file in &xml_files {
            eprintln!("  - {:?}", file);
        }
    }
    
    let mut configs = Vec::new();
    let mut failed_files = Vec::new();
    
    for file_path in xml_files {
        match load_single_config(&file_path) {
            Ok(config) => {
                if verbose {
                    eprintln!("Successfully loaded: {:?}", file_path);
                }
                configs.push(config);
            },
            Err(e) => {
                eprintln!("Error loading {:?}: {}", file_path, e);
                failed_files.push((file_path, e));
            }
        }
    }
    
    if configs.is_empty() {
        return Err(format!("All {} XML files failed to load", failed_files.len()).into());
    }
    
    if !failed_files.is_empty() && verbose {
        eprintln!("Warning: {} files failed to load but continuing with {} valid files", 
                  failed_files.len(), configs.len());
    }
    
    Ok(merge_configs(configs))
}
```

#### 3. Library Extension (`lib.rs`)
Add merge functionality to the library:
```rust
impl NacmConfig {
    pub fn merge(configs: Vec<NacmConfig>) -> Self {
        // Implementation as outlined above
    }
    
    pub fn default() -> Self {
        // Provide sensible defaults when no configs are found
    }
}
```

#### 4. File Discovery Function
```rust
use std::fs;

fn discover_xml_files(dir: &PathBuf) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut xml_files = Vec::new();
    
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        
        if path.is_file() && is_valid_xml_file(&path) {
            xml_files.push(path);
        }
    }
    
    // Sort for deterministic order
    xml_files.sort();
    Ok(xml_files)
}

fn is_valid_xml_file(path: &PathBuf) -> bool {
    if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
        // Skip hidden files
        if filename.starts_with('.') {
            return false;
        }
        
        // Skip backup/temporary files
        if filename.ends_with('~') || filename.ends_with(".bak") || 
           filename.ends_with(".orig") || filename.starts_with(".tmp") {
            return false;
        }
        
        // Must end with .xml (case insensitive)
        filename.to_lowercase().ends_with(".xml")
    } else {
        false
    }
}
```

## 5. Merge Conflict Resolution

### Group Conflicts
- **Same group name, different users**: Merge user lists (union)
- **Same group name, different GID**: Last file wins, emit warning
- **Duplicate users in same group**: Deduplicate silently

### Rule List Conflicts
- **Same rule list name**: Merge rules from both lists
- **Rule ordering**: Maintain original order within files, but adjust global precedence
- **Duplicate rule names within same rule list**: Allow (names are for human reference)

### Global Setting Conflicts
- **Different default policies**: Last file wins, emit warning if verbose
- **NACM enable/disable conflicts**: Last file wins, emit warning
- **Logging setting conflicts**: Last file wins

## 6. Testing Strategy

### Unit Tests
- Test file discovery with various directory contents
- Test merge logic with conflicting configurations  
- Test error handling for malformed files
- Test alphabetical sorting behavior

### Integration Tests
- Test `--config-dir` vs `--config` mutual exclusion
- Test verbose output shows discovered files
- Test behavior with empty directories
- Test partial failure scenarios (some files invalid)

### Example Test Configurations
Create test data with multiple files:
- `01-groups.xml`: Define user groups
- `02-global.xml`: Set global policies
- `03-admin-rules.xml`: Administrative rules
- `04-user-rules.xml`: Regular user rules

## 7. Documentation Updates

### README Updates
- Add examples of `--config-dir` usage
- Document merge behavior and file processing order
- Explain best practices for organizing multiple files

### CLI Help Updates
- Update usage examples
- Document mutual exclusion of config options
- Add troubleshooting section for merge conflicts

## 8. Best Practices Guidance

### File Organization Recommendations
- **Naming**: Use numeric prefixes for control over merge order
  - `01-global-defaults.xml`
  - `10-groups.xml` 
  - `20-admin-rules.xml`
  - `30-user-rules.xml`

- **Separation of Concerns**: Split by functionality
  - Groups and users in separate files
  - Rules by department/team
  - Global settings in dedicated file

- **Environment-Specific**: Use directory structure
  - `config/prod/` vs `config/dev/` vs `config/test/`

### Migration Strategy
- Existing single-file users: No changes required
- For multiple files: Move to `--config-dir` gradually
- Test merged configuration against single-file version

## 9. Backward Compatibility

- Existing `--config` option remains unchanged
- All current functionality preserved
- No breaking changes to API or library interface
- Existing XML files work exactly as before

## 10. Future Enhancements

### Possible Extensions
- Recursive directory scanning (`--config-dir-recursive`)
- Custom file patterns (`--config-pattern "*.nacm"`)
- Configuration validation mode (`--validate-only`)
- Merge conflict reporting (`--report-conflicts`)
- Environment variable substitution in configs

This implementation plan maintains full backward compatibility while providing powerful new functionality for managing complex NACM configurations across multiple files.
