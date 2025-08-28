use nacm_validator::{AccessRequest, NacmConfig, Operation, RuleEffect, RequestContext};
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load the NACM configuration from the XML file
    // Use a more robust path resolution
    let xml_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join("data")
        .join("aaa_ncm_init.xml");
    
    let xml_content = std::fs::read_to_string(&xml_path)
        .map_err(|e| format!("Failed to read XML file at {:?}: {}", xml_path, e))?;
    
    let config = NacmConfig::from_xml(&xml_content)?;
    
    println!("NACM Configuration loaded:");
    println!("- NACM enabled: {}", config.enable_nacm);
    println!("- Default policies: read={:?}, write={:?}, exec={:?}",
             config.read_default, config.write_default, config.exec_default);
    println!("- Command default policies: cmd_read={:?}, cmd_exec={:?}",
             config.cmd_read_default, config.cmd_exec_default);
    println!("- Groups: {:?}", config.groups.keys().collect::<Vec<_>>());
    println!("- Rule lists: {}", config.rule_lists.len());
    
    // Test different access scenarios
    let netconf_context = RequestContext::NETCONF;
    let test_cases = vec![
        ("Admin executing edit-config", AccessRequest {
            user: "admin",
            module_name: None,
            rpc_name: Some("edit-config"),
            operation: Operation::Exec,
            path: None,
            context: Some(&netconf_context),
            command: None,
        }),
        ("Oper executing edit-config", AccessRequest {
            user: "oper",
            module_name: None,
            rpc_name: Some("edit-config"),
            operation: Operation::Exec,
            path: None,
            context: Some(&netconf_context),
            command: None,
        }),
        ("Oper modifying NACM config", AccessRequest {
            user: "oper",
            module_name: Some("ietf-netconf-acm"),
            rpc_name: None,
            operation: Operation::Update,
            path: Some("/"),
            context: Some(&netconf_context),
            command: None,
        }),
        ("Guest reading example/misc/data", AccessRequest {
            user: "Guest",
            module_name: Some("example"),
            rpc_name: None,
            operation: Operation::Read,
            path: Some("/misc/data"),
            context: Some(&netconf_context),
            command: None,
        }),
        ("Guest creating example/misc", AccessRequest {
            user: "Guest",
            module_name: Some("example"),
            rpc_name: None,
            operation: Operation::Create,
            path: Some("/misc"),
            context: Some(&netconf_context),
            command: None,
        }),
        ("Unknown user reading data", AccessRequest {
            user: "unknown",
            module_name: Some("test"),
            rpc_name: None,
            operation: Operation::Read,
            path: Some("/data"),
            context: Some(&netconf_context),
            command: None,
        }),
    ];
    
    println!("\nAccess validation results:");
    for (description, request) in test_cases {
        let result = config.validate(&request);
        let result_str = match result.effect {
            RuleEffect::Permit => "✅ PERMIT",
            RuleEffect::Deny => "❌ DENY",
        };
        let log_str = if result.should_log { " [LOG]" } else { "" };
        println!("- {}: {}{}", description, result_str, log_str);
    }
    
    Ok(())
}
