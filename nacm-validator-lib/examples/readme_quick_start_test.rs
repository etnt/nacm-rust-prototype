use nacm_validator::{AccessRequest, NacmConfig, Operation, RequestContext};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let xml_content = std::fs::read_to_string("examples/data/tailf_acm_example.xml")?;
    let config = NacmConfig::from_xml(&xml_content)?;
    let context = RequestContext::CLI;

    let request = AccessRequest {
        user: "alice",
        operation: Operation::Read,
        context: Some(&context),
        command: Some("show status"),
        module_name: None,
        rpc_name: None,
        path: None,
    };

    let result = config.validate(&request);
    println!("Access {}: {}", 
             if result.effect == nacm_validator::RuleEffect::Permit { "GRANTED" } else { "DENIED" },
             if result.should_log { "[LOGGED]" } else { "" });
    
    Ok(())
}
