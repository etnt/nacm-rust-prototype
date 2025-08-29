use nacm_validator::{AccessRequest, NacmConfig, Operation, RuleEffect, RequestContext};
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔧 Comprehensive Tail-f ACM Extensions Demo");
    println!("{}", "=".repeat(50));
    
    // Load the Tail-f ACM example configuration
    let xml_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join("data")
        .join("tailf_acm_example.xml");
    
    let xml_content = std::fs::read_to_string(&xml_path)
        .map_err(|e| format!("Failed to read XML file at {:?}: {}", xml_path, e))?;
    
    let config = NacmConfig::from_xml(&xml_content)?;
    
    println!("📋 Configuration Summary:");
    println!("- NACM enabled: {}", config.enable_nacm);
    println!("- Standard defaults: read={:?}, write={:?}, exec={:?}", 
             config.read_default, config.write_default, config.exec_default);
    println!("- Command defaults: cmd_read={:?}, cmd_exec={:?}",
             config.cmd_read_default, config.cmd_exec_default);
    println!("- Logging: default_permit={}, default_deny={}",
             config.log_if_default_permit, config.log_if_default_deny);
    println!();
    
    // Show detailed group information
    println!("👥 Groups:");
    for (name, group) in &config.groups {
        let gid_info = group.gid.map(|g| format!(" (GID: {})", g)).unwrap_or_default();
        println!("  {} {}: {:?}", name, gid_info, group.users);
    }
    println!();
    
    // Show rule lists with detailed breakdown
    println!("📜 Rule Lists:");
    for (i, rule_list) in config.rule_lists.iter().enumerate() {
        println!("  {}. {} (groups: {:?})", i + 1, rule_list.name, rule_list.groups);
        println!("     - Standard rules: {}", rule_list.rules.len());
        for rule in &rule_list.rules {
            let context_info = rule.context.as_ref()
                .map(|c| format!(" [context: {}]", c))
                .unwrap_or_default();
            println!("       • {} -> {:?}{}", rule.name, rule.effect, context_info);
        }
        println!("     - Command rules: {}", rule_list.command_rules.len());
        for cmd_rule in &rule_list.command_rules {
            let context_info = cmd_rule.context.as_ref()
                .map(|c| format!(" [context: {}]", c))
                .unwrap_or_default();
            let command_info = cmd_rule.command.as_ref()
                .map(|c| format!(" [command: {}]", c))
                .unwrap_or_default();
            println!("       • {} -> {:?}{}{}", cmd_rule.name, cmd_rule.effect, context_info, command_info);
        }
    }
    println!();
    
    // Test comprehensive scenarios
    let cli_context = RequestContext::CLI;
    let webui_context = RequestContext::WebUI;
    let netconf_context = RequestContext::NETCONF;
    
    println!("🧪 Test Scenarios:");
    println!();
    
    // Group 1: Command-based access control
    println!("1️⃣ Command-Based Access Control:");
    let command_tests = vec![
        ("alice (operator) - CLI 'show status'", AccessRequest {
            user: "alice",
            module_name: None,
            rpc_name: None,
            operation: Operation::Read,
            path: None,
            context: Some(&cli_context),
            command: Some("show status"),
        }),
        ("bob (operator) - CLI 'show interfaces'", AccessRequest {
            user: "bob",
            module_name: None,
            rpc_name: None,
            operation: Operation::Read,
            path: None,
            context: Some(&cli_context),
            command: Some("show interfaces"),
        }),
        ("alice (operator) - WebUI 'help'", AccessRequest {
            user: "alice",
            module_name: None,
            rpc_name: None,
            operation: Operation::Read,
            path: None,
            context: Some(&webui_context),
            command: Some("help"),
        }),
        ("charlie (not in group) - CLI 'show status'", AccessRequest {
            user: "charlie",
            module_name: None,
            rpc_name: None,
            operation: Operation::Read,
            path: None,
            context: Some(&cli_context),
            command: Some("show status"),
        }),
        ("alice (operator) - CLI 'reboot' (exec operation)", AccessRequest {
            user: "alice",
            module_name: None,
            rpc_name: None,
            operation: Operation::Exec,
            path: None,
            context: Some(&cli_context),
            command: Some("reboot"),
        }),
        ("admin - CLI 'reboot' (exec operation)", AccessRequest {
            user: "admin",
            module_name: None,
            rpc_name: None,
            operation: Operation::Exec,
            path: None,
            context: Some(&cli_context),
            command: Some("reboot"),
        }),
    ];
    
    for (description, request) in command_tests {
        let result = config.validate(&request);
        let result_icon = match result.effect {
            RuleEffect::Permit => "✅",
            RuleEffect::Deny => "❌",
        };
        let log_indicator = if result.should_log { " 📝" } else { "" };
        println!("   {} {}: {:?}{}", result_icon, description, 
                 result.effect, log_indicator);
    }
    println!();
    
    // Group 2: Context-aware data access
    println!("2️⃣ Context-Aware Data Access:");
    let data_tests = vec![
        ("alice - NETCONF read interfaces", AccessRequest {
            user: "alice",
            module_name: Some("ietf-interfaces"),
            rpc_name: None,
            operation: Operation::Read,
            path: Some("/interfaces"),
            context: Some(&netconf_context),
            command: None,
        }),
        ("alice - CLI read interfaces (no command rule)", AccessRequest {
            user: "alice",
            module_name: Some("ietf-interfaces"),
            rpc_name: None,
            operation: Operation::Read,
            path: Some("/interfaces"),
            context: Some(&cli_context),
            command: None,
        }),
        ("alice - WebUI read interfaces (no command rule)", AccessRequest {
            user: "alice",
            module_name: Some("ietf-interfaces"),
            rpc_name: None,
            operation: Operation::Read,
            path: Some("/interfaces"),
            context: Some(&webui_context),
            command: None,
        }),
        ("admin - NETCONF edit-config RPC", AccessRequest {
            user: "admin",
            module_name: None,
            rpc_name: Some("edit-config"),
            operation: Operation::Exec,
            path: None,
            context: Some(&netconf_context),
            command: None,
        }),
        ("alice - NETCONF edit-config RPC (should deny)", AccessRequest {
            user: "alice",
            module_name: None,
            rpc_name: Some("edit-config"),
            operation: Operation::Exec,
            path: None,
            context: Some(&netconf_context),
            command: None,
        }),
    ];
    
    for (description, request) in data_tests {
        let result = config.validate(&request);
        let result_icon = match result.effect {
            RuleEffect::Permit => "✅",
            RuleEffect::Deny => "❌",
        };
        let log_indicator = if result.should_log { " 📝" } else { "" };
        println!("   {} {}: {:?}{}", result_icon, description, 
                 result.effect, log_indicator);
    }
    println!();
    
    // Group 3: Default behavior testing
    println!("3️⃣ Default Behavior Testing:");
    let default_tests = vec![
        ("unknown_user - CLI unknown command (cmd_read_default)", AccessRequest {
            user: "unknown_user",
            module_name: None,
            rpc_name: None,
            operation: Operation::Read,
            path: None,
            context: Some(&cli_context),
            command: Some("unknown-command"),
        }),
        ("unknown_user - CLI exec unknown command (cmd_exec_default)", AccessRequest {
            user: "unknown_user",
            module_name: None,
            rpc_name: None,
            operation: Operation::Exec,
            path: None,
            context: Some(&cli_context),
            command: Some("unknown-exec-command"),
        }),
        ("unknown_user - NETCONF read data (read_default)", AccessRequest {
            user: "unknown_user",
            module_name: Some("unknown-module"),
            rpc_name: None,
            operation: Operation::Read,
            path: Some("/unknown/path"),
            context: Some(&netconf_context),
            command: None,
        }),
        ("unknown_user - NETCONF write data (write_default)", AccessRequest {
            user: "unknown_user",
            module_name: Some("unknown-module"),
            rpc_name: None,
            operation: Operation::Update,
            path: Some("/unknown/path"),
            context: Some(&netconf_context),
            command: None,
        }),
    ];
    
    for (description, request) in default_tests {
        let result = config.validate(&request);
        let result_icon = match result.effect {
            RuleEffect::Permit => "✅",
            RuleEffect::Deny => "❌",
        };
        let log_indicator = if result.should_log { " 📝" } else { "" };
        println!("   {} {}: {:?}{}", result_icon, description, 
                 result.effect, log_indicator);
    }
    println!();
    
    // Group 4: Mixed scenarios
    println!("4️⃣ Mixed Command and Data Access:");
    let mixed_tests = vec![
        ("alice - CLI with both command and module (command takes priority)", AccessRequest {
            user: "alice",
            module_name: Some("ietf-interfaces"),
            rpc_name: None,
            operation: Operation::Read,
            path: Some("/interfaces"),
            context: Some(&cli_context),
            command: Some("show status"),
        }),
        ("bob - WebUI with both command and RPC (command takes priority)", AccessRequest {
            user: "bob",
            module_name: None,
            rpc_name: Some("get"),
            operation: Operation::Read,
            path: None,
            context: Some(&webui_context),
            command: Some("help"),
        }),
    ];
    
    for (description, request) in mixed_tests {
        let result = config.validate(&request);
        let result_icon = match result.effect {
            RuleEffect::Permit => "✅",
            RuleEffect::Deny => "❌",
        };
        let log_indicator = if result.should_log { " 📝" } else { "" };
        println!("   {} {}: {:?}{}", result_icon, description, 
                 result.effect, log_indicator);
    }
    println!();
    
    println!("📊 Summary of Tail-f ACM Features Demonstrated:");
    println!("✓ Command-based access control (cmdrule elements)");
    println!("✓ Context-aware rules (cli, webui, netconf contexts)");
    println!("✓ Enhanced logging controls (log-if-permit, log-if-deny)");
    println!("✓ Group ID mapping (gid attributes)");
    println!("✓ Command defaults (cmd-read-default, cmd-exec-default)");
    println!("✓ Mixed command and data access scenarios");
    println!("✓ Fallback to traditional NACM rules when no command rules match");
    println!();
    
    println!("🎯 Key Takeaways:");
    println!("1. Command rules have priority over data rules when command is specified");
    println!("2. Context matters - same user can have different access via different interfaces");
    println!("3. Enhanced logging provides audit trail capabilities");
    println!("4. Default command policies provide fallback behavior");
    println!("5. Tail-f ACM is backward compatible with standard NACM");
    
    Ok(())
}
