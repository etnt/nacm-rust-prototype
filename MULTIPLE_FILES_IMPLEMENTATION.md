# Multiple Config Files - Implementation Examples

This document provides concrete code examples and test cases for implementing the `--config-dir` functionality outlined in MULTIPLE_FILES_PLAN.md.

## Example Directory Structure

```
config/
├── 01-global-settings.xml    # Global NACM settings and defaults
├── 10-groups.xml             # User groups definition  
├── 20-admin-rules.xml        # Administrative access rules
├── 30-operator-rules.xml     # Operator access rules
└── 99-fallback-rules.xml     # Catch-all rules at lowest priority
```

## 1. Sample Configuration Files

### 01-global-settings.xml
```xml
<config xmlns="http://tail-f.com/ns/config/1.0">
  <nacm xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-acm">
    <enable-nacm>true</enable-nacm>
    <read-default>deny</read-default>
    <write-default>deny</write-default>
    <exec-default>deny</exec-default>
    <cmd-read-default xmlns="http://tail-f.com/yang/acm">permit</cmd-read-default>
    <cmd-exec-default xmlns="http://tail-f.com/yang/acm">deny</cmd-exec-default>
    <log-if-default-permit xmlns="http://tail-f.com/yang/acm"/>
  </nacm>
</config>
```

### 10-groups.xml
```xml
<config xmlns="http://tail-f.com/ns/config/1.0">
  <nacm xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-acm">
    <groups>
      <group>
        <name>admin</name>
        <user-name>alice</user-name>
        <user-name>bob</user-name>
        <gid xmlns="http://tail-f.com/yang/acm">1000</gid>
      </group>
      <group>
        <name>operators</name>
        <user-name>charlie</user-name>
        <user-name>diana</user-name>
        <gid xmlns="http://tail-f.com/yang/acm">2000</gid>
      </group>
    </groups>
  </nacm>
</config>
```

### 20-admin-rules.xml
```xml
<config xmlns="http://tail-f.com/ns/config/1.0">
  <nacm xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-acm">
    <rule-list>
      <name>admin-rules</name>
      <group>admin</group>
      <rule>
        <name>allow-all-rpcs</name>
        <rpc-name>*</rpc-name>
        <access-operations>exec</access-operations>
        <action>permit</action>
        <log-if-permit xmlns="http://tail-f.com/yang/acm"/>
      </rule>
      <rule>
        <name>allow-all-data</name>
        <path>/</path>
        <access-operations>*</access-operations>
        <action>permit</action>
      </rule>
    </rule-list>
  </nacm>
</config>
```

### 30-operator-rules.xml
```xml
<config xmlns="http://tail-f.com/ns/config/1.0">
  <nacm xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-acm">
    <rule-list>
      <name>operator-rules</name>
      <group>operators</group>
      <rule>
        <name>deny-edit-config</name>
        <rpc-name>edit-config</rpc-name>
        <access-operations>exec</access-operations>
        <action>deny</action>
        <log-if-deny xmlns="http://tail-f.com/yang/acm"/>
      </rule>
      <rule>
        <name>allow-get-operations</name>
        <rpc-name>get</rpc-name>
        <access-operations>exec</access-operations>
        <action>permit</action>
      </rule>
      <cmdrule xmlns="http://tail-f.com/yang/acm">
        <name>cli-show-commands</name>
        <context>cli</context>
        <command>show *</command>
        <access-operations>read exec</access-operations>
        <action>permit</action>
      </cmdrule>
    </rule-list>
  </nacm>
</config>
```

## 2. Core Implementation Code

### CLI Argument Parsing
```rust
use clap::{Parser, Args};
use std::path::PathBuf;

#[derive(Parser)]
#[command(author, version, about = "NACM Access Control Validator")]
struct Cli {
    #[command(flatten)]
    config_source: ConfigSource,
    
    // ... other fields remain the same
}

#[derive(Args)]
#[group(required = true, multiple = false)]
struct ConfigSource {
    /// Path to the NACM XML configuration file
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Path to directory containing NACM XML configuration files
    #[arg(long)]
    config_dir: Option<PathBuf>,
}
```

### Configuration Loading
```rust
use std::fs;
use std::path::{Path, PathBuf};

fn load_configs(cli: &Cli) -> Result<NacmConfig, Box<dyn std::error::Error>> {
    match &cli.config_source {
        ConfigSource { config: Some(file), .. } => {
            if cli.verbose {
                eprintln!("Loading single config file: {:?}", file);
            }
            load_single_config(file)
        },
        ConfigSource { config_dir: Some(dir), .. } => {
            if cli.verbose {
                eprintln!("Loading config directory: {:?}", dir);
            }
            load_directory_configs(dir, cli.verbose)
        },
        _ => unreachable!("clap ensures one option is present"),
    }
}

fn load_directory_configs(dir: &Path, verbose: bool) -> Result<NacmConfig, Box<dyn std::error::Error>> {
    // Validate directory exists
    if !dir.is_dir() {
        return Err(format!("Config directory does not exist: {:?}", dir).into());
    }

    // Discover XML files
    let xml_files = discover_xml_files(dir)?;
    
    if xml_files.is_empty() {
        eprintln!("Warning: No XML files found in directory {:?}", dir);
        return Ok(create_default_config());
    }

    if verbose {
        eprintln!("Found {} XML configuration files:", xml_files.len());
        for (idx, file) in xml_files.iter().enumerate() {
            eprintln!("  {}. {:?}", idx + 1, file.file_name().unwrap_or_default());
        }
    }

    // Load and parse each file
    let mut configs = Vec::new();
    let mut errors = Vec::new();

    for file_path in &xml_files {
        match load_single_config(file_path) {
            Ok(config) => {
                if verbose {
                    eprintln!("✓ Successfully loaded: {:?}", file_path.file_name().unwrap_or_default());
                }
                configs.push(config);
            },
            Err(e) => {
                let error_msg = format!("Failed to load {:?}: {}", file_path.file_name().unwrap_or_default(), e);
                eprintln!("✗ {}", error_msg);
                errors.push(error_msg);
            }
        }
    }

    // Check if we have any valid configurations
    if configs.is_empty() {
        return Err(format!(
            "All {} configuration files failed to load:\n{}",
            xml_files.len(),
            errors.join("\n")
        ).into());
    }

    if !errors.is_empty() {
        eprintln!("Warning: {} out of {} files failed to load, continuing with {} valid configurations", 
                  errors.len(), xml_files.len(), configs.len());
    }

    // Merge configurations
    if verbose {
        eprintln!("Merging {} configurations...", configs.len());
    }
    
    let merged_config = NacmConfig::merge(configs)?;
    
    if verbose {
        eprintln!("✓ Configuration merge completed");
        eprintln!("  - {} groups loaded", merged_config.groups.len());
        eprintln!("  - {} rule lists loaded", merged_config.rule_lists.len());
        let total_rules: usize = merged_config.rule_lists.iter()
            .map(|rl| rl.rules.len() + rl.command_rules.len())
            .sum();
        eprintln!("  - {} total rules loaded", total_rules);
    }

    Ok(merged_config)
}

fn discover_xml_files(dir: &Path) -> Result<Vec<PathBuf>, std::io::Error> {
    let mut xml_files = Vec::new();
    
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        
        if path.is_file() && is_valid_xml_file(&path) {
            xml_files.push(path);
        }
    }
    
    // Sort alphabetically for deterministic processing order
    xml_files.sort();
    Ok(xml_files)
}

fn is_valid_xml_file(path: &Path) -> bool {
    if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
        // Skip hidden files and backup files
        if filename.starts_with('.') || 
           filename.ends_with('~') || 
           filename.ends_with(".bak") || 
           filename.ends_with(".orig") ||
           filename.contains(".tmp") {
            return false;
        }
        
        // Must have .xml extension (case insensitive)
        filename.to_lowercase().ends_with(".xml")
    } else {
        false
    }
}

fn create_default_config() -> NacmConfig {
    NacmConfig {
        enable_nacm: false,  // Safe default when no configs found
        read_default: RuleEffect::Deny,
        write_default: RuleEffect::Deny,
        exec_default: RuleEffect::Deny,
        cmd_read_default: RuleEffect::Permit,
        cmd_exec_default: RuleEffect::Deny,
        log_if_default_permit: false,
        log_if_default_deny: false,
        groups: HashMap::new(),
        rule_lists: Vec::new(),
    }
}
```

### Configuration Merging Logic
```rust
use std::collections::HashMap;

impl NacmConfig {
    pub fn merge(mut configs: Vec<NacmConfig>) -> Result<Self, Box<dyn std::error::Error>> {
        if configs.is_empty() {
            return Ok(create_default_config());
        }
        
        if configs.len() == 1 {
            return Ok(configs.into_iter().next().unwrap());
        }
        
        let mut merged = create_default_config();
        
        // Process each config in order (earlier files have priority for rules)
        for (file_index, config) in configs.into_iter().enumerate() {
            merge_single_config(&mut merged, config, file_index)?;
        }
        
        Ok(merged)
    }
}

fn merge_single_config(
    merged: &mut NacmConfig, 
    config: NacmConfig, 
    file_index: usize
) -> Result<(), Box<dyn std::error::Error>> {
    
    // Merge leaf values (last file wins)
    merged.enable_nacm = config.enable_nacm;
    merged.read_default = config.read_default;
    merged.write_default = config.write_default;
    merged.exec_default = config.exec_default;
    merged.cmd_read_default = config.cmd_read_default;
    merged.cmd_exec_default = config.cmd_exec_default;
    merged.log_if_default_permit = config.log_if_default_permit;
    merged.log_if_default_deny = config.log_if_default_deny;
    
    // Merge groups
    for (group_name, group) in config.groups {
        merge_group(&mut merged.groups, group_name, group)?;
    }
    
    // Merge rule lists with adjusted ordering
    for mut rule_list in config.rule_lists {
        // Adjust rule orders to maintain precedence across files
        adjust_rule_orders(&mut rule_list, file_index);
        merge_rule_list(&mut merged.rule_lists, rule_list)?;
    }
    
    Ok(())
}

fn merge_group(
    existing_groups: &mut HashMap<String, NacmGroup>, 
    group_name: String, 
    new_group: NacmGroup
) -> Result<(), Box<dyn std::error::Error>> {
    
    match existing_groups.get_mut(&group_name) {
        Some(existing_group) => {
            // Merge users (avoid duplicates)
            for user in new_group.users {
                if !existing_group.users.contains(&user) {
                    existing_group.users.push(user);
                }
            }
            
            // Handle GID conflicts
            if existing_group.gid != new_group.gid {
                if existing_group.gid.is_some() && new_group.gid.is_some() {
                    eprintln!("Warning: Group '{}' GID conflict: {} -> {}", 
                              group_name, 
                              existing_group.gid.unwrap(), 
                              new_group.gid.unwrap());
                }
                existing_group.gid = new_group.gid; // Later file wins
            }
        },
        None => {
            // New group, add directly
            existing_groups.insert(group_name, new_group);
        }
    }
    
    Ok(())
}

fn adjust_rule_orders(rule_list: &mut NacmRuleList, file_index: usize) {
    let base_order = file_index as u32 * 10000;
    
    // Adjust regular rules
    for (rule_index, rule) in rule_list.rules.iter_mut().enumerate() {
        rule.order = base_order + rule_index as u32;
    }
    
    // Adjust command rules
    for (rule_index, cmd_rule) in rule_list.command_rules.iter_mut().enumerate() {
        cmd_rule.order = base_order + rule_index as u32;
    }
}

fn merge_rule_list(
    existing_rule_lists: &mut Vec<NacmRuleList>, 
    new_rule_list: NacmRuleList
) -> Result<(), Box<dyn std::error::Error>> {
    
    // Find existing rule list with same name
    if let Some(existing_list) = existing_rule_lists.iter_mut()
        .find(|rl| rl.name == new_rule_list.name) {
        
        // Merge groups
        for group in new_rule_list.groups {
            if !existing_list.groups.contains(&group) {
                existing_list.groups.push(group);
            }
        }
        
        // Append rules (maintaining order)
        existing_list.rules.extend(new_rule_list.rules);
        existing_list.command_rules.extend(new_rule_list.command_rules);
        
    } else {
        // New rule list, add directly
        existing_rule_lists.push(new_rule_list);
    }
    
    Ok(())
}
```

## 3. Test Cases

### Unit Test Examples
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_discover_xml_files() {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();
        
        // Create test files
        fs::write(dir_path.join("01-config.xml"), "<config/>").unwrap();
        fs::write(dir_path.join("02-CONFIG.XML"), "<config/>").unwrap();
        fs::write(dir_path.join("ignored.txt"), "text").unwrap();
        fs::write(dir_path.join(".hidden.xml"), "<config/>").unwrap();
        fs::write(dir_path.join("backup.xml~"), "<config/>").unwrap();
        
        let files = discover_xml_files(dir_path).unwrap();
        assert_eq!(files.len(), 2);
        assert!(files[0].ends_with("01-config.xml"));
        assert!(files[1].ends_with("02-CONFIG.XML"));
    }

    #[test]
    fn test_group_merge() {
        let mut groups = HashMap::new();
        
        // Add initial group
        let group1 = NacmGroup {
            name: "admin".to_string(),
            users: vec!["alice".to_string()],
            gid: Some(1000),
        };
        merge_group(&mut groups, "admin".to_string(), group1).unwrap();
        
        // Merge with additional user
        let group2 = NacmGroup {
            name: "admin".to_string(),
            users: vec!["bob".to_string(), "alice".to_string()], // alice duplicate
            gid: Some(1000),
        };
        merge_group(&mut groups, "admin".to_string(), group2).unwrap();
        
        let merged_group = &groups["admin"];
        assert_eq!(merged_group.users.len(), 2); // No duplicates
        assert!(merged_group.users.contains(&"alice".to_string()));
        assert!(merged_group.users.contains(&"bob".to_string()));
    }

    #[test]
    fn test_rule_order_adjustment() {
        let mut rule_list = NacmRuleList {
            name: "test".to_string(),
            groups: vec!["admin".to_string()],
            rules: vec![
                NacmRule { order: 0, ..create_test_rule("rule1") },
                NacmRule { order: 1, ..create_test_rule("rule2") },
            ],
            command_rules: vec![],
        };
        
        adjust_rule_orders(&mut rule_list, 2); // File index 2
        
        assert_eq!(rule_list.rules[0].order, 20000); // 2 * 10000 + 0
        assert_eq!(rule_list.rules[1].order, 20001); // 2 * 10000 + 1
    }

    #[test]
    fn test_config_merge_precedence() {
        let config1 = NacmConfig {
            enable_nacm: false,
            read_default: RuleEffect::Permit,
            ..create_default_config()
        };
        
        let config2 = NacmConfig {
            enable_nacm: true,
            read_default: RuleEffect::Deny,
            ..create_default_config()
        };
        
        let merged = NacmConfig::merge(vec![config1, config2]).unwrap();
        
        // Last config wins for leaf values
        assert_eq!(merged.enable_nacm, true);
        assert_eq!(merged.read_default, RuleEffect::Deny);
    }

    fn create_test_rule(name: &str) -> NacmRule {
        NacmRule {
            name: name.to_string(),
            module_name: None,
            rpc_name: None,
            path: None,
            access_operations: HashSet::new(),
            effect: RuleEffect::Permit,
            order: 0,
            context: None,
            log_if_permit: false,
            log_if_deny: false,
        }
    }
}
```

## 4. Usage Examples

### Command Line Usage
```bash
# Single file (existing behavior)
nacm-validator --config /etc/nacm/config.xml --user alice --operation read

# Directory of files (new behavior)  
nacm-validator --config-dir /etc/nacm/config.d --user alice --operation read

# Verbose output shows file loading
nacm-validator --config-dir /etc/nacm/config.d --verbose --user alice --operation read

# JSON input with directory config
echo '{"user":"alice","operation":"read"}' | \
  nacm-validator --config-dir /etc/nacm/config.d --json-input
```

### Expected Output with Verbose Mode
```
Found 4 XML configuration files:
  1. "01-global-settings.xml"
  2. "10-groups.xml" 
  3. "20-admin-rules.xml"
  4. "30-operator-rules.xml"
✓ Successfully loaded: "01-global-settings.xml"
✓ Successfully loaded: "10-groups.xml"
✓ Successfully loaded: "20-admin-rules.xml"
✓ Successfully loaded: "30-operator-rules.xml"
Merging 4 configurations...
✓ Configuration merge completed
  - 2 groups loaded
  - 2 rule lists loaded
  - 5 total rules loaded
User: alice
Operation: Read
Decision: PERMIT
```

This implementation provides a robust, well-tested foundation for supporting multiple configuration files while maintaining full backward compatibility with existing single-file usage.
