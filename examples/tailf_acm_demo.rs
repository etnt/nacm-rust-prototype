use nacm_validator::{AccessRequest, NacmConfig, Operation, RuleEffect, RequestContext};
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load the Tail-f ACM example configuration
    let xml_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join("data")
        .join("tailf_acm_example.xml");
    
    let xml_content = std::fs::read_to_string(&xml_path)
        .map_err(|e| format!("Failed to read XML file at {:?}: {}", xml_path, e))?;
    
    let config = NacmConfig::from_xml(&xml_content)?;
    
    println!("🔧 Tail-f ACM Configuration loaded:");
    println!("- NACM enabled: {}", config.enable_nacm);
    println!("- Default policies:");
    println!("  * Data: read={:?}, write={:?}, exec={:?}", 
             config.read_default, config.write_default, config.exec_default);
    println!("  * Commands: cmd_read={:?}, cmd_exec={:?}",
             config.cmd_read_default, config.cmd_exec_default);
    println!("- Logging: default_permit={}, default_deny={}",
             config.log_if_default_permit, config.log_if_default_deny);
    println!("- Groups: {:?}", config.groups.keys().collect::<Vec<_>>());
    
    // Show group details with GIDs
    for (name, group) in &config.groups {
        let gid_str = if let Some(gid) = group.gid {
            format!(" (GID: {})", gid)
        } else {
            String::new()
        };
        println!("  * {}{}: {:?}", name, gid_str, group.users);
    }
    
    println!("- Rule lists: {}", config.rule_lists.len());
    for rule_list in &config.rule_lists {
        println!("  * {}: {} rules, {} command rules", 
                 rule_list.name, rule_list.rules.len(), rule_list.command_rules.len());
    }
    
    // Test command access scenarios
    println!("\n🔍 Command access validation results:");
    
    let cli_context = RequestContext::CLI;
    let webui_context = RequestContext::WebUI;
    let netconf_context = RequestContext::NETCONF;
    
    let command_test_cases = vec![
        ("Alice (operator) - CLI show status", AccessRequest {
            user: "alice",
            module_name: None,
            rpc_name: None,
            operation: Operation::Read,
            path: None,
            context: Some(&cli_context),
            command: Some("show status"),
        }),
        ("Alice (operator) - CLI show interfaces", AccessRequest {
            user: "alice",
            module_name: None,
            rpc_name: None,
            operation: Operation::Read,
            path: None,
            context: Some(&cli_context),
            command: Some("show interfaces"),
        }),
        ("Alice (operator) - WebUI help", AccessRequest {
            user: "alice",
            module_name: None,
            rpc_name: None,
            operation: Operation::Read,
            path: None,
            context: Some(&webui_context),
            command: Some("help"),
        }),
        ("Alice (operator) - CLI reboot (should deny)", AccessRequest {
            user: "alice",
            module_name: None,
            rpc_name: None,
            operation: Operation::Exec,
            path: None,
            context: Some(&cli_context),
            command: Some("reboot"),
        }),
        ("Admin - CLI reboot (should permit)", AccessRequest {
            user: "admin",
            module_name: None,
            rpc_name: None,
            operation: Operation::Exec,
            path: None,
            context: Some(&cli_context),
            command: Some("reboot"),
        }),
        ("Bob (operator) - Unknown command (should use default)", AccessRequest {
            user: "bob",
            module_name: None,
            rpc_name: None,
            operation: Operation::Exec,
            path: None,
            context: Some(&cli_context),
            command: Some("unknown-command"),
        }),
    ];
    
    for (description, request) in command_test_cases {
        let result = config.validate(&request);
        let result_icon = match result.effect {
            RuleEffect::Permit => "✅",
            RuleEffect::Deny => "❌",
        };
        let log_str = if result.should_log { " 📝[LOG]" } else { "" };
        println!("  {} {}: {}{}", result_icon, description, 
                 format!("{:?}", result.effect).to_uppercase(), log_str);
    }
    
    // Test mixed data and command access
    println!("\n📊 Mixed data access validation:");
    
    let data_test_cases = vec![
        ("Alice - NETCONF read interfaces", AccessRequest {
            user: "alice",
            module_name: Some("ietf-interfaces"),
            rpc_name: None,
            operation: Operation::Read,
            path: Some("/interfaces"),
            context: Some(&netconf_context),
            command: None,
        }),
        ("Alice - NETCONF write interfaces (should deny)", AccessRequest {
            user: "alice",
            module_name: None,
            rpc_name: Some("edit-config"),
            operation: Operation::Exec,
            path: None,
            context: Some(&netconf_context),
            command: None,
        }),
        ("Admin - NETCONF write (should permit)", AccessRequest {
            user: "admin",
            module_name: None,
            rpc_name: Some("edit-config"),
            operation: Operation::Exec,
            path: None,
            context: Some(&netconf_context),
            command: None,
        }),
    ];
    
    for (description, request) in data_test_cases {
        let result = config.validate(&request);
        let result_icon = match result.effect {
            RuleEffect::Permit => "✅",
            RuleEffect::Deny => "❌",
        };
        let log_str = if result.should_log { " 📝[LOG]" } else { "" };
        println!("  {} {}: {}{}", result_icon, description, 
                 format!("{:?}", result.effect).to_uppercase(), log_str);
    }
    
    println!("\n🎯 Summary:");
    println!("The Tail-f ACM extensions provide:");
    println!("- Command-based access control for CLI/WebUI operations");
    println!("- Enhanced logging controls for audit trails");
    println!("- Group ID mapping for OS integration");
    println!("- Context-aware rules (CLI vs NETCONF vs WebUI)");
    println!("- Granular control over what gets logged");
    
    Ok(())
}
