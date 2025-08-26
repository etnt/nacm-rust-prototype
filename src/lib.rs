//! # NACM (Network Access Control Model) Implementation
//!
//! This library implements NACM (RFC 8341) access control validation in Rust.
//! It provides functionality to:
//! - Parse real-world NACM XML configurations
//! - Validate access requests against defined rules
//! - Handle user groups and rule precedence
//! - Support various operations (CRUD + exec) and path matching
//!
//! ## Quick Start
//!
//! ```rust
//! use nacm_rust_prototype::{NacmConfig, AccessRequest, Operation};
//!
//! // Load configuration from XML
//! let xml_content = r#"<?xml version="1.0" encoding="UTF-8"?>
//! <config xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-acm">
//!   <nacm>
//!     <enable-nacm>true</enable-nacm>
//!     <read-default>permit</read-default>
//!     <write-default>deny</write-default>
//!     <exec-default>permit</exec-default>
//!     <groups>
//!       <group>
//!         <name>admin</name>
//!         <user-name>alice</user-name>
//!       </group>
//!     </groups>
//!     <rule-list>
//!       <name>admin-acl</name>
//!       <group>admin</group>
//!       <rule>
//!         <name>permit-all</name>
//!         <action>permit</action>
//!       </rule>
//!     </rule-list>
//!   </nacm>
//! </config>"#;
//! let config = NacmConfig::from_xml(&xml_content)?;
//!
//! // Create an access request
//! let request = AccessRequest {
//!     user: "alice",
//!     module_name: Some("ietf-interfaces"),
//!     rpc_name: None,
//!     operation: Operation::Read,
//!     path: Some("/interfaces"),
//! };
//!
//! // Validate the request
//! let result = config.validate(&request);
//! println!("Access result: {:?}", result); // RuleEffect::Permit or RuleEffect::Deny
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// NACM Rule effect (permit or deny)
/// 
/// This enum represents the final decision for an access request.
/// In NACM, every rule must have an action that either permits or denies access.
/// 
/// # Examples
/// 
/// ```
/// use nacm_rust_prototype::RuleEffect;
/// 
/// let permit = RuleEffect::Permit;
/// let deny = RuleEffect::Deny;
/// 
/// // Rules with permit effects allow access
/// assert_eq!(permit == RuleEffect::Permit, true);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")] // Serializes as "permit"/"deny" in JSON/XML
pub enum RuleEffect {
    /// Allow the requested access
    Permit,
    /// Deny the requested access
    Deny,
}

/// Implementation of `FromStr` trait for `RuleEffect`
/// 
/// This allows parsing rule effects from strings (used when parsing XML).
/// Case-insensitive parsing: "PERMIT", "permit", "Permit" all work.
impl std::str::FromStr for RuleEffect {
    type Err = String;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "permit" => Ok(RuleEffect::Permit),
            "deny" => Ok(RuleEffect::Deny),
            _ => Err(format!("Unknown rule effect: {}", s)),
        }
    }
}

/// NACM operations enumeration
/// 
/// Represents the different types of operations that can be performed
/// in a NETCONF/RESTCONF system. Maps to standard CRUD operations plus exec.
/// 
/// # Examples
/// 
/// ```
/// use nacm_rust_prototype::Operation;
/// 
/// let read_op = Operation::Read;
/// let write_op = Operation::Update;
/// 
/// // Operations can be compared
/// assert_ne!(read_op, write_op);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Operation {
    /// Reading/retrieving data (GET operations)
    Read,
    /// Creating new data (POST operations)
    Create,
    /// Modifying existing data (PUT/PATCH operations)
    Update,
    /// Removing data (DELETE operations)
    Delete,
    /// Executing RPCs or actions (RPC operations)
    Exec,
}

/// Implementation of `FromStr` trait for `Operation`
/// 
/// Enables parsing operations from strings, used in CLI and XML parsing.
/// Case-insensitive: "READ", "read", "Read" all parse to `Operation::Read`.
impl std::str::FromStr for Operation {
    type Err = String;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "read" => Ok(Operation::Read),
            "create" => Ok(Operation::Create),
            "update" => Ok(Operation::Update),
            "delete" => Ok(Operation::Delete),
            "exec" => Ok(Operation::Exec),
            _ => Err(format!("Unknown operation: {}", s)),
        }
    }
}

/// NACM Rule structure (extended to match XML format)
/// 
/// Represents a single NACM access control rule. Each rule defines:
/// - What it applies to (module, RPC, path)
/// - Which operations it covers
/// - Whether it permits or denies access
/// - Its precedence order (lower numbers = higher priority)
/// 
/// # Fields
/// 
/// * `name` - Human-readable identifier for the rule
/// * `module_name` - YANG module this rule applies to (None = any module)
/// * `rpc_name` - Specific RPC name (None = any RPC, "*" = wildcard)
/// * `path` - XPath or data path (None = any path, "/" = root)
/// * `access_operations` - Set of operations this rule covers
/// * `effect` - Whether to permit or deny matching requests
/// * `order` - Rule precedence (lower = higher priority)
/// 
/// # Examples
/// 
/// ```
/// use nacm_rust_prototype::{NacmRule, RuleEffect, Operation};
/// use std::collections::HashSet;
/// 
/// let mut ops = HashSet::new();
/// ops.insert(Operation::Read);
/// 
/// let rule = NacmRule {
///     name: "allow-read-interfaces".to_string(),
///     module_name: Some("ietf-interfaces".to_string()),
///     rpc_name: None,
///     path: Some("/interfaces".to_string()),
///     access_operations: ops,
///     effect: RuleEffect::Permit,
///     order: 10,
/// };
/// ```
#[derive(Debug, Clone)]
pub struct NacmRule {
    /// Unique name for this rule
    pub name: String,
    /// YANG module name this rule applies to (None = any module)
    pub module_name: Option<String>,
    /// RPC name this rule applies to (None = any RPC)
    pub rpc_name: Option<String>,
    /// XPath or data path (None = any path)
    pub path: Option<String>,
    /// Set of operations covered by this rule
    pub access_operations: HashSet<Operation>,
    /// Whether this rule permits or denies access
    pub effect: RuleEffect,
    /// Rule precedence - lower numbers have higher priority
    pub order: u32,
}

/// NACM Rule List with associated groups
/// 
/// A rule list is a named collection of rules that applies to specific user groups.
/// Rule lists are processed in order, and within each list, rules are ordered by priority.
/// 
/// # Fields
/// 
/// * `name` - Identifier for this rule list
/// * `groups` - User groups this rule list applies to
/// * `rules` - Ordered list of access control rules
/// 
/// # Examples
/// 
/// ```
/// use nacm_rust_prototype::{NacmRuleList, NacmRule, RuleEffect, Operation};
/// use std::collections::HashSet;
/// 
/// let rule_list = NacmRuleList {
///     name: "admin-rules".to_string(),
///     groups: vec!["admin".to_string()],
///     rules: vec![], // Would contain actual rules
/// };
/// ```
#[derive(Debug, Clone)]
pub struct NacmRuleList {
    /// Name of this rule list
    pub name: String,
    /// User groups this rule list applies to
    pub groups: Vec<String>,
    /// Ordered list of rules in this list
    pub rules: Vec<NacmRule>,
}

/// NACM Group definition
/// 
/// Represents a named group of users. Groups are used to organize users
/// and apply rule lists to multiple users at once.
/// 
/// # Fields
/// 
/// * `name` - Group identifier (e.g., "admin", "operators")
/// * `users` - List of usernames belonging to this group
/// 
/// # Examples
/// 
/// ```
/// use nacm_rust_prototype::NacmGroup;
/// 
/// let admin_group = NacmGroup {
///     name: "admin".to_string(),
///     users: vec!["alice".to_string(), "bob".to_string()],
/// };
/// ```
#[derive(Debug, Clone)]
pub struct NacmGroup {
    /// Name of the group
    pub name: String,
    /// List of usernames in this group
    pub users: Vec<String>,
}

/// Full NACM configuration
/// 
/// The main configuration object that contains all NACM settings:
/// - Global enable/disable flag
/// - Default policies for different operation types
/// - User groups and their members
/// - Rule lists with access control rules
/// 
/// # Fields
/// 
/// * `enable_nacm` - Global NACM enable flag
/// * `read_default` - Default policy for read operations
/// * `write_default` - Default policy for write operations (create/update/delete)
/// * `exec_default` - Default policy for exec operations (RPC calls)
/// * `groups` - Map of group names to group definitions
/// * `rule_lists` - List of rule lists, processed in order
/// 
/// # Examples
/// 
/// ```
/// use nacm_rust_prototype::{NacmConfig, RuleEffect};
/// use std::collections::HashMap;
/// 
/// let config = NacmConfig {
///     enable_nacm: true,
///     read_default: RuleEffect::Deny,
///     write_default: RuleEffect::Deny,
///     exec_default: RuleEffect::Deny,
///     groups: HashMap::new(),
///     rule_lists: vec![],
/// };
/// ```
#[derive(Debug, Clone)]
pub struct NacmConfig {
    /// Global NACM enable flag - if false, all access is permitted
    pub enable_nacm: bool,
    /// Default policy for read operations when no rules match
    pub read_default: RuleEffect,
    /// Default policy for write operations (create/update/delete) when no rules match
    pub write_default: RuleEffect,
    /// Default policy for exec operations (RPCs) when no rules match
    pub exec_default: RuleEffect,
    /// Map of group name to group definition
    pub groups: HashMap<String, NacmGroup>,
    /// Ordered list of rule lists
    pub rule_lists: Vec<NacmRuleList>,
}

/// Represents an access request for validation
/// 
/// This structure contains all the information needed to validate
/// an access request against NACM rules. Uses borrowed string slices
/// for efficiency (avoids copying strings).
/// 
/// # Lifetimes
/// 
/// The `'a` lifetime parameter ensures that this struct doesn't outlive
/// the data it references. This is Rust's way of preventing dangling pointers.
/// 
/// # Fields
/// 
/// * `user` - Username making the request
/// * `module_name` - YANG module being accessed (if applicable)
/// * `rpc_name` - RPC being called (if applicable)
/// * `operation` - Type of operation being performed
/// * `path` - Data path being accessed (if applicable)
/// 
/// # Examples
/// 
/// ```
/// use nacm_rust_prototype::{AccessRequest, Operation};
/// 
/// let request = AccessRequest {
///     user: "alice",
///     module_name: Some("ietf-interfaces"),
///     rpc_name: None,
///     operation: Operation::Read,
///     path: Some("/interfaces/interface[name='eth0']"),
/// };
/// ```
pub struct AccessRequest<'a> {
    /// Username making the access request
    pub user: &'a str,
    /// YANG module name being accessed (None if not module-specific)
    pub module_name: Option<&'a str>,
    /// RPC name being called (None if not an RPC call)
    pub rpc_name: Option<&'a str>,
    /// Type of operation being performed
    pub operation: Operation,
    /// XPath or data path being accessed (None if not path-specific)
    pub path: Option<&'a str>,
}

// ============================================================================
// XML Parsing Structures
// ============================================================================
//
// The following structures are used internally for parsing XML configuration
// files. They mirror the XML schema and use serde attributes to handle
// the conversion from XML elements to Rust structs.
//
// These are separate from the main API structs to:
// 1. Handle XML-specific naming (kebab-case vs snake_case)
// 2. Deal with XML structure differences (nested elements, attributes)
// 3. Keep the public API clean and independent of XML format
//
// The #[derive(Deserialize)] enables automatic XML parsing via serde-xml-rs.
// The #[serde(rename = "...")] attributes map XML element names to Rust fields.
// ============================================================================

/// Root XML configuration element
/// 
/// Maps to the top-level `<config>` element in NACM XML files.
/// Contains the main `<nacm>` configuration block.
#[derive(Debug, Deserialize)]
struct XmlConfig {
    /// The main NACM configuration block
    #[serde(rename = "nacm")]
    pub nacm: XmlNacm,
}

/// Main NACM configuration element from XML
/// 
/// Maps to the `<nacm>` element and contains all NACM settings:
/// global flags, default policies, groups, and rule lists.
#[derive(Debug, Deserialize)]
struct XmlNacm {
    /// Global NACM enable flag (XML: <enable-nacm>)
    #[serde(rename = "enable-nacm")]
    pub enable_nacm: bool,
    /// Default policy for read operations (XML: <read-default>)
    #[serde(rename = "read-default")]
    pub read_default: String,
    /// Default policy for write operations (XML: <write-default>)
    #[serde(rename = "write-default")]
    pub write_default: String,
    /// Default policy for exec operations (XML: <exec-default>)
    #[serde(rename = "exec-default")]
    pub exec_default: String,
    /// Container for all groups (XML: <groups>)
    pub groups: XmlGroups,
    /// List of rule lists (XML: <rule-list> elements)
    #[serde(rename = "rule-list")]
    pub rule_lists: Vec<XmlRuleList>,
}

/// Container for group definitions from XML
/// 
/// Maps to the `<groups>` element which contains multiple `<group>` elements.
#[derive(Debug, Deserialize)]
struct XmlGroups {
    /// List of individual group definitions
    pub group: Vec<XmlGroup>,
}

/// Individual group definition from XML
/// 
/// Maps to a `<group>` element containing group name and user list.
#[derive(Debug, Deserialize)]
struct XmlGroup {
    /// Group name (XML: <name>)
    pub name: String,
    /// List of usernames in this group (XML: <user-name> elements)
    /// The `default` attribute provides an empty vector if no users are specified
    #[serde(rename = "user-name", default)]
    pub user_names: Vec<String>,
}

/// Rule list definition from XML
/// 
/// Maps to a `<rule-list>` element containing the rule list metadata
/// and the actual access control rules.
#[derive(Debug, Deserialize)]
struct XmlRuleList {
    /// Rule list name (XML: <name>)
    pub name: String,
    /// Group this rule list applies to (XML: <group>)
    pub group: String,
    /// List of rules in this rule list (XML: <rule> elements)
    /// The `default` attribute provides an empty vector if no rules are specified
    #[serde(default)]
    pub rule: Vec<XmlRule>,
}

/// Individual access control rule from XML
/// 
/// Maps to a `<rule>` element with all its sub-elements.
/// Optional fields use `Option<T>` to handle missing XML elements.
#[derive(Debug, Deserialize)]
struct XmlRule {
    /// Rule name (XML: <name>)
    pub name: String,
    /// YANG module name this rule applies to (XML: <module-name>)
    #[serde(rename = "module-name")]
    pub module_name: Option<String>,
    /// RPC name this rule applies to (XML: <rpc-name>)
    #[serde(rename = "rpc-name")]
    pub rpc_name: Option<String>,
    /// XPath or data path (XML: <path>)
    pub path: Option<String>,
    /// Space-separated list of operations (XML: <access-operations>)
    #[serde(rename = "access-operations")]
    pub access_operations: Option<String>,
    /// Rule effect: "permit" or "deny" (XML: <action>)
    pub action: String,
}

impl NacmConfig {
    /// Parse NACM configuration from XML string
    /// 
    /// This function takes an XML string containing NACM configuration
    /// and parses it into a `NacmConfig` struct. It handles the conversion
    /// from the XML schema to our internal representation.
    /// 
    /// # Arguments
    /// 
    /// * `xml_content` - String slice containing the XML configuration
    /// 
    /// # Returns
    /// 
    /// * `Ok(NacmConfig)` - Successfully parsed configuration
    /// * `Err(Box<dyn Error>)` - Parsing failed (malformed XML, unknown values, etc.)
    /// 
    /// # Examples
    /// 
    /// ```rust
    /// use nacm_rust_prototype::NacmConfig;
    /// 
    /// let xml = r#"
    /// <config xmlns="http://tail-f.com/ns/config/1.0">
    ///   <nacm xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-acm">
    ///     <enable-nacm>true</enable-nacm>
    ///     <read-default>deny</read-default>
    ///     <write-default>deny</write-default>
    ///     <exec-default>deny</exec-default>
    ///     <groups>
    ///       <group>
    ///         <name>admin</name>
    ///         <user-name>alice</user-name>
    ///       </group>
    ///     </groups>
    ///     <rule-list>
    ///       <name>admin-rules</name>
    ///       <group>admin</group>
    ///     </rule-list>
    ///   </nacm>
    /// </config>
    /// "#;
    /// 
    /// let config = NacmConfig::from_xml(xml).unwrap();
    /// assert_eq!(config.enable_nacm, true);
    /// ```
    pub fn from_xml(xml_content: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // Step 1: Parse XML into intermediate structures
        // serde_xml_rs automatically deserializes the XML based on our struct definitions
        let xml_config: XmlConfig = serde_xml_rs::from_str(xml_content)?;
        
        // Step 2: Convert XML groups to our internal representation
        // Transform from XML format to HashMap for efficient lookups
        let mut groups = HashMap::new();
        for xml_group in xml_config.nacm.groups.group {
            // Create internal group representation and add to HashMap for O(1) lookup
            groups.insert(xml_group.name.clone(), NacmGroup {
                name: xml_group.name,
                users: xml_group.user_names,
            });
        }
        
        // Step 3: Convert XML rule lists to our internal representation
        // Process each rule list and assign ordering for rule precedence
        let mut rule_lists = Vec::new();
        for (order_base, xml_rule_list) in xml_config.nacm.rule_lists.iter().enumerate() {
            let mut rules = Vec::new();
            
            // Process each rule within this rule list
            for (rule_order, xml_rule) in xml_rule_list.rule.iter().enumerate() {
                // Step 3a: Parse access operations from string format
                // Handle both wildcard ("*") and space-separated operation lists
                let mut access_operations = HashSet::new();
                if let Some(ops_str) = &xml_rule.access_operations {
                    if ops_str.trim() == "*" {
                        // Wildcard means all operations
                        access_operations.insert(Operation::Read);
                        access_operations.insert(Operation::Create);
                        access_operations.insert(Operation::Update);
                        access_operations.insert(Operation::Delete);
                        access_operations.insert(Operation::Exec);
                    } else {
                        // Parse space-separated operation names like "read write"
                        for op in ops_str.split_whitespace() {
                            if let Ok(operation) = op.parse::<Operation>() {
                                access_operations.insert(operation);
                            }
                            // Note: Invalid operations are silently ignored
                        }
                    }
                }
                
                // Step 3b: Parse the rule effect (permit/deny)
                let effect = xml_rule.action.parse::<RuleEffect>()?;
                
                // Step 3c: Create internal rule representation
                // Calculate rule order: rule list order * 1000 + rule position
                // This ensures rules in earlier rule lists have higher priority
                rules.push(NacmRule {
                    name: xml_rule.name.clone(),
                    module_name: xml_rule.module_name.clone(),
                    rpc_name: xml_rule.rpc_name.clone(),
                    path: xml_rule.path.clone(),
                    access_operations,
                    effect,
                    // Calculate rule priority: list_position * 1000 + rule_position
                    // This ensures proper ordering across multiple rule lists
                    order: (order_base * 1000 + rule_order) as u32,
                });
            }
            
            // Step 3d: Create the rule list with its associated group
            // Note: XML format has single group per rule list, our internal format supports multiple
            rule_lists.push(NacmRuleList {
                name: xml_rule_list.name.clone(),
                groups: vec![xml_rule_list.group.clone()],  // Wrap single group in Vec
                rules,
            });
        }
        
        // Step 4: Create the final configuration object
        // Parse default policies from strings and assemble everything
        Ok(NacmConfig {
            enable_nacm: xml_config.nacm.enable_nacm,
            // Parse default policy strings ("permit"/"deny") to enum values
            read_default: xml_config.nacm.read_default.parse()?,
            write_default: xml_config.nacm.write_default.parse()?,
            exec_default: xml_config.nacm.exec_default.parse()?,
            groups,
            rule_lists,
        })
    }
    
    /// Validate an access request against the NACM configuration
    /// 
    /// This is the main validation function that determines whether an access
    /// request should be permitted or denied based on the NACM rules.
    /// 
    /// # Algorithm
    /// 
    /// 1. If NACM is disabled globally, permit all access
    /// 2. Find all groups the user belongs to
    /// 3. Collect all matching rules from applicable rule lists
    /// 4. Sort rules by precedence (order field)
    /// 5. Return the effect of the first matching rule
    /// 6. If no rules match, apply the appropriate default policy
    /// 
    /// # Arguments
    /// 
    /// * `req` - The access request to validate
    /// 
    /// # Returns
    /// 
    /// * `RuleEffect::Permit` - Access should be allowed
    /// * `RuleEffect::Deny` - Access should be denied
    /// 
    /// # Examples
    /// 
    /// ```rust
    /// use nacm_rust_prototype::{NacmConfig, AccessRequest, Operation, RuleEffect};
    /// 
    /// # let config = NacmConfig {
    /// #     enable_nacm: true,
    /// #     read_default: RuleEffect::Deny,
    /// #     write_default: RuleEffect::Deny,
    /// #     exec_default: RuleEffect::Deny,
    /// #     groups: std::collections::HashMap::new(),
    /// #     rule_lists: vec![],
    /// # };
    /// let request = AccessRequest {
    ///     user: "alice",
    ///     module_name: Some("ietf-interfaces"),
    ///     rpc_name: None,
    ///     operation: Operation::Read,
    ///     path: Some("/interfaces"),
    /// };
    /// 
    /// let result = config.validate(&request);
    /// // Result will be Permit or Deny based on the rules
    /// ```
    pub fn validate(&self, req: &AccessRequest) -> RuleEffect {
        // Step 1: If NACM is disabled, permit all access
        if !self.enable_nacm {
            return RuleEffect::Permit;
        }
        
        // Step 2: Find all groups this user belongs to
        // Uses functional programming style with iterator chains
        let user_groups: Vec<&str> = self.groups
            .iter()                    // Iterator over (group_name, group) pairs
            .filter_map(|(group_name, group)| {  // Transform and filter in one step
                if group.users.contains(&req.user.to_string()) {
                    Some(group_name.as_str())  // Include this group name
                } else {
                    None                       // Skip this group
                }
            })
            .collect();                // Collect into a Vec
        
        // Step 3: Collect all matching rules from applicable rule lists
        let mut all_matches = Vec::new();
        
        for rule_list in &self.rule_lists {
            // Check if this rule list applies to any of the user's groups
            let applies = rule_list.groups.iter().any(|group| {
                group == "*" ||                              // Wildcard group
                user_groups.contains(&group.as_str())        // User is in this group
            });
            
            if applies {
                // Check each rule in this rule list
                for rule in &rule_list.rules {
                    if self.rule_matches(rule, req) {
                        all_matches.push(rule);
                    }
                }
            }
        }
        
        // Step 4: Sort rules by precedence (lower order = higher priority)
        // This ensures we process the most important rules first
        all_matches.sort_by_key(|r| r.order);
        
        // Step 5: Return the effect of the first (highest priority) matching rule
        if let Some(rule) = all_matches.first() {
            rule.effect
        } else {
            // Step 6: No rules matched - apply default policy based on operation type
            match req.operation {
                Operation::Read => self.read_default,
                // Group write operations together (create/update/delete)
                Operation::Create | Operation::Update | Operation::Delete => self.write_default,
                Operation::Exec => self.exec_default,
            }
        }
    }
    
    /// Check if a rule matches an access request
    /// 
    /// This private helper function determines whether a specific rule
    /// applies to a given access request. A rule matches if ALL of its
    /// conditions are satisfied (AND logic).
    /// 
    /// # Matching Logic
    /// 
    /// * **Operations**: Rule must cover the requested operation
    /// * **Module**: Rule's module must match (or be unspecified)
    /// * **RPC**: Rule's RPC must match (or be wildcard/unspecified)
    /// * **Path**: Rule's path must match (with wildcard support)
    /// 
    /// # Arguments
    /// 
    /// * `rule` - The rule to check
    /// * `req` - The access request to match against
    /// 
    /// # Returns
    /// 
    /// * `true` if the rule matches the request
    /// * `false` if any condition fails
    fn rule_matches(&self, rule: &NacmRule, req: &AccessRequest) -> bool {
        // Check 1: Operations - Rule must cover the requested operation
        // If rule specifies operations, the request operation must be included
        if !rule.access_operations.is_empty() && !rule.access_operations.contains(&req.operation) {
            return false;  // Rule doesn't cover this operation
        }
        
        // Check 2: Module name matching
        // If rule specifies a module, request must be for the same module
        if let Some(rule_module) = &rule.module_name {
            if let Some(req_module) = req.module_name {
                if rule_module != req_module {
                    return false;  // Different modules
                }
            } else {
                return false;  // Rule requires module, but request has none
            }
        }
        
        // Check 3: RPC name matching
        // Special handling for wildcard ("*") RPCs
        if let Some(rule_rpc) = &rule.rpc_name {
            if rule_rpc == "*" {
                // Wildcard matches any RPC (or no RPC)
            } else if let Some(req_rpc) = req.rpc_name {
                if rule_rpc != req_rpc {
                    return false;  // Different RPC names
                }
            } else {
                return false;  // Rule requires specific RPC, but request has none
            }
        }
        
        // Check 4: Path matching (simplified XPath-style matching)
        // Supports exact matches and simple wildcard patterns
        if let Some(rule_path) = &rule.path {
            if rule_path == "/" {
                // Root path matches everything (universal path rule)
            } else if let Some(req_path) = req.path {
                if rule_path.ends_with("/*") {
                    // Wildcard path: "/interfaces/*" matches "/interfaces/interface[1]"
                    let prefix = &rule_path[..rule_path.len() - 2];
                    if !req_path.starts_with(prefix) {
                        return false;  // Path doesn't match prefix
                    }
                } else if rule_path != req_path {
                    return false;  // Exact path mismatch
                }
            } else {
                return false;  // Rule requires path, but request has none
            }
        }
        
        // All checks passed - rule matches this request
        true
    }
}

// --- Example usage and tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xml_parsing() {
        let xml = r#"
        <config xmlns="http://tail-f.com/ns/config/1.0">
            <nacm xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-acm">
                <enable-nacm>true</enable-nacm>
                <read-default>deny</read-default>
                <write-default>deny</write-default>
                <exec-default>deny</exec-default>
                <groups>
                    <group>
                        <name>admin</name>
                        <user-name>admin</user-name>
                    </group>
                </groups>
                <rule-list>
                    <name>admin</name>
                    <group>admin</group>
                    <rule>
                        <name>any-rpc</name>
                        <rpc-name>*</rpc-name>
                        <access-operations>exec</access-operations>
                        <action>permit</action>
                    </rule>
                </rule-list>
            </nacm>
        </config>"#;
        
        let config = NacmConfig::from_xml(xml).unwrap();
        assert_eq!(config.enable_nacm, true);
        assert_eq!(config.read_default, RuleEffect::Deny);
        assert_eq!(config.groups.len(), 1);
        assert_eq!(config.rule_lists.len(), 1);
    }

    #[test]
    fn test_nacm_validation_admin() {
        let xml = r#"
        <config xmlns="http://tail-f.com/ns/config/1.0">
            <nacm xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-acm">
                <enable-nacm>true</enable-nacm>
                <read-default>deny</read-default>
                <write-default>deny</write-default>
                <exec-default>deny</exec-default>
                <groups>
                    <group>
                        <name>admin</name>
                        <user-name>admin</user-name>
                    </group>
                </groups>
                <rule-list>
                    <name>admin</name>
                    <group>admin</group>
                    <rule>
                        <name>any-rpc</name>
                        <rpc-name>*</rpc-name>
                        <access-operations>exec</access-operations>
                        <action>permit</action>
                    </rule>
                </rule-list>
            </nacm>
        </config>"#;
        
        let config = NacmConfig::from_xml(xml).unwrap();
        
        let req = AccessRequest {
            user: "admin",
            module_name: None,
            rpc_name: Some("edit-config"),
            operation: Operation::Exec,
            path: None,
        };
        
        assert_eq!(config.validate(&req), RuleEffect::Permit);
    }

    #[test]
    fn test_real_nacm_xml() {
        use std::path::Path;
        
        let xml_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("examples")
            .join("data")
            .join("aaa_ncm_init.xml");
            
        let xml = std::fs::read_to_string(&xml_path)
            .expect(&format!("Failed to read XML file at {:?}", xml_path));
        
        let config = NacmConfig::from_xml(&xml).expect("Failed to parse XML");
        
        // Test admin user - should be able to execute any RPC
        let admin_req = AccessRequest {
            user: "admin",
            module_name: None,
            rpc_name: Some("edit-config"),
            operation: Operation::Exec,
            path: None,
        };
        assert_eq!(config.validate(&admin_req), RuleEffect::Permit);
        
        // Test oper user - should be denied edit-config
        let oper_req = AccessRequest {
            user: "oper",
            module_name: None,
            rpc_name: Some("edit-config"),
            operation: Operation::Exec,
            path: None,
        };
        assert_eq!(config.validate(&oper_req), RuleEffect::Deny);
        
        // Test oper user - should be denied writing to nacm module
        let nacm_write_req = AccessRequest {
            user: "oper",
            module_name: Some("ietf-netconf-acm"),
            rpc_name: None,
            operation: Operation::Update,
            path: Some("/"),
        };
        assert_eq!(config.validate(&nacm_write_req), RuleEffect::Deny);
        
        // Test any user with example module - should be permitted for /misc/*
        let example_req = AccessRequest {
            user: "Guest",
            module_name: Some("example"),
            rpc_name: None,
            operation: Operation::Read,
            path: Some("/misc/foo"),
        };
        assert_eq!(config.validate(&example_req), RuleEffect::Permit);
        
        // Test configuration loaded properly
        assert_eq!(config.enable_nacm, true);
        assert_eq!(config.read_default, RuleEffect::Deny);
        assert_eq!(config.write_default, RuleEffect::Deny);
        assert_eq!(config.exec_default, RuleEffect::Deny);
        
        // Check groups
        assert_eq!(config.groups.len(), 2);
        assert!(config.groups.contains_key("admin"));
        assert!(config.groups.contains_key("oper"));
        
        let admin_group = &config.groups["admin"];
        assert_eq!(admin_group.users, vec!["admin", "private"]);
        
        let oper_group = &config.groups["oper"];
        assert_eq!(oper_group.users, vec!["oper", "public"]);
        
        // Check rule lists
        assert_eq!(config.rule_lists.len(), 3);
        
        println!("Successfully parsed {} groups and {} rule lists", 
                 config.groups.len(), config.rule_lists.len());
    }
}