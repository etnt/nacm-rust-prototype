use nacm_rust_prototype::{AccessRequest, NacmConfig, Operation, RuleEffect};
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
    println!("- Groups: {:?}", config.groups.keys().collect::<Vec<_>>());
    println!("- Rule lists: {}", config.rule_lists.len());
    
    // Test different access scenarios
    let test_cases = vec![
        ("Admin executing edit-config", AccessRequest {
            user: "admin",
            module_name: None,
            rpc_name: Some("edit-config"),
            operation: Operation::Exec,
            path: None,
        }),
        ("Oper executing edit-config", AccessRequest {
            user: "oper",
            module_name: None,
            rpc_name: Some("edit-config"),
            operation: Operation::Exec,
            path: None,
        }),
        ("Oper modifying NACM config", AccessRequest {
            user: "oper",
            module_name: Some("ietf-netconf-acm"),
            rpc_name: None,
            operation: Operation::Update,
            path: Some("/"),
        }),
        ("Guest reading example/misc/data", AccessRequest {
            user: "Guest",
            module_name: Some("example"),
            rpc_name: None,
            operation: Operation::Read,
            path: Some("/misc/data"),
        }),
        ("Guest creating example/misc", AccessRequest {
            user: "Guest",
            module_name: Some("example"),
            rpc_name: None,
            operation: Operation::Create,
            path: Some("/misc"),
        }),
        ("Unknown user reading data", AccessRequest {
            user: "unknown",
            module_name: Some("test"),
            rpc_name: None,
            operation: Operation::Read,
            path: Some("/data"),
        }),
    ];
    
    println!("\nAccess validation results:");
    for (description, request) in test_cases {
        let result = config.validate(&request);
        let result_str = match result {
            RuleEffect::Permit => "✅ PERMIT",
            RuleEffect::Deny => "❌ DENY",
        };
        println!("- {}: {}", description, result_str);
    }
    
    Ok(())
}
