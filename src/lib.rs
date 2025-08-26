//! Simple prototype for validating NACM (RFC 8341) rules in Rust.

use std::collections::{HashMap, HashSet};

/// NACM Rule effect (permit or deny)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleEffect {
    Permit,
    Deny,
}

/// NACM Rule structure
#[derive(Debug, Clone)]
pub struct NacmRule {
    pub name: String,
    pub module: Option<String>,
    pub operation: Option<String>, // "read", "write", "exec", etc.
    pub path: Option<String>,      // XPath or data node path
    pub users: HashSet<String>,    // Usernames or groups
    pub effect: RuleEffect,
    pub order: u32,                // Lower is higher precedence
}

/// NACM Rule List (policy set)
#[derive(Debug, Clone)]
pub struct NacmRuleList {
    pub rules: Vec<NacmRule>,
}

/// Represents an access request
pub struct AccessRequest<'a> {
    pub user: &'a str,
    pub module: Option<&'a str>,
    pub operation: Option<&'a str>,
    pub path: Option<&'a str>,
}

impl NacmRuleList {
    /// Validate an access request against the rule list
    pub fn validate(&self, req: &AccessRequest) -> Option<RuleEffect> {
        // Find all matching rules, sorted by order
        let mut matches: Vec<&NacmRule> = self.rules.iter()
            .filter(|rule| {
                (rule.users.contains(req.user))
                    && (rule.module.as_deref() == req.module || rule.module.is_none())
                    && (rule.operation.as_deref() == req.operation || rule.operation.is_none())
                    && (rule.path.as_deref() == req.path || rule.path.is_none())
            })
            .collect();

        matches.sort_by_key(|r| r.order);

        matches.first().map(|r| r.effect)
    }
}

// --- Example usage and test ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nacm_validation() {
        let mut users = HashSet::new();
        users.insert("alice".to_owned());
        let rule = NacmRule {
            name: "allow-alice-read".to_string(),
            module: Some("ietf-interfaces".to_string()),
            operation: Some("read".to_string()),
            path: Some("/interfaces".to_string()),
            users,
            effect: RuleEffect::Permit,
            order: 10,
        };

        let rules = NacmRuleList { rules: vec![rule] };

        let req = AccessRequest {
            user: "alice",
            module: Some("ietf-interfaces"),
            operation: Some("read"),
            path: Some("/interfaces"),
        };

        assert_eq!(rules.validate(&req), Some(RuleEffect::Permit));
    }
}