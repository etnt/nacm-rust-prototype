//! # NACM Validator CLI Tool
//! 
//! A command-line interface for validating access requests against NACM (Network Access Control Model) configurations.
//! 
//! This binary provides a convenient way to:
//! - Validate single access requests with exit code feedback for shell scripts
//! - Process batch requests from JSON input
//! - Output results in multiple formats (text, JSON, exit-code only)
//! - Integrate NACM validation into automation pipelines
//! 
//! ## Usage Examples
//! 
//! ### Single Request Validation
//! ```bash
//! # Basic validation with text output
//! nacm-validator --config config.xml --user alice --operation read --module ietf-interfaces
//! 
//! # JSON output for programmatic processing
//! nacm-validator --config config.xml --user bob --operation exec --rpc edit-config --format json
//! 
//! # Exit code only for shell scripting
//! if nacm-validator --config config.xml --user charlie --operation create --format exit-code; then
//!     echo "Access granted"
//! fi
//! ```
//! 
//! ### Batch Processing
//! ```bash
//! # Process multiple requests from JSON
//! echo '{"user":"alice","operation":"read","module":"ietf-interfaces"}' | \
//!   nacm-validator --config config.xml --json-input
//! ```
//! 
//! ## Exit Codes
//! 
//! - **0**: Access permitted
//! - **1**: Access denied  
//! - **2**: Error (invalid config, missing file, etc.)

use clap::{Parser, ValueEnum};
use nacm_validator::{AccessRequest, NacmConfig, Operation, RuleEffect, RequestContext};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process;

/// Command-line interface structure for the NACM validator
/// 
/// This struct defines all the command-line arguments and options.
/// The `#[derive(Parser)]` attribute generates the argument parsing code automatically
/// using the `clap` crate, which is Rust's standard CLI argument parser.
/// 
/// ## Field Details
/// 
/// Fields are made `Option<T>` when they're not required in all modes.
/// For example, `--user` and `--operation` are required for single request mode
/// but not needed when using `--json-input` for batch processing.
#[derive(Parser)]
#[command(author, version, about = "NACM Access Control Validator", long_about = None)]
struct Cli {
    /// Path to the NACM XML configuration file
    /// 
    /// This is the only truly required argument in all modes.
    /// The configuration file contains the NACM groups, rules, and policies.
    #[arg(short, long)]
    config: PathBuf,

    /// Username making the request
    /// 
    /// Optional because it's not needed in JSON input mode where the username
    /// comes from the JSON payload instead.
    #[arg(short, long)]
    user: Option<String>,

    /// Module name (optional)
    /// 
    /// YANG module name that the access request pertains to.
    /// If not specified, the request is not module-specific.
    #[arg(short, long)]
    module: Option<String>,

    /// RPC name (optional)
    /// 
    /// Name of the RPC being called. Use "*" for wildcard matching.
    /// If not specified, the request is not RPC-specific.
    #[arg(short, long)]
    rpc: Option<String>,

    /// Operation type
    /// 
    /// The type of operation being performed. Optional in JSON mode
    /// where it comes from the JSON payload.
    #[arg(short, long)]
    operation: Option<OperationArg>,

    /// Path (optional)
    /// 
    /// XPath or data path for the access request.
    /// Supports simple wildcard patterns like "/interfaces/*".
    #[arg(short, long)]
    path: Option<String>,

    /// Request context (optional)
    /// 
    /// The management interface or context from which the request originates.
    /// Used for Tail-f ACM context-aware access control.
    #[arg(short = 'x', long)]
    context: Option<ContextArg>,

    /// Command (optional)
    /// 
    /// Command being executed (for command-based access control).
    /// Used with Tail-f ACM command rules for CLI and WebUI access.
    #[arg(short = 'C', long)]
    command: Option<String>,

    /// Output format
    /// 
    /// Controls how results are displayed:
    /// - `text`: Human-readable output (default)
    /// - `json`: Structured JSON for programmatic processing
    /// - `exit-code`: No output, only exit codes (for shell scripting)
    #[arg(long, default_value = "text")]
    format: OutputFormat,

    /// Verbose output
    /// 
    /// Shows additional information like configuration summary,
    /// rule matching details, and group membership.
    #[arg(short, long)]
    verbose: bool,

    /// JSON input mode - read request from stdin
    /// 
    /// When enabled, the tool reads JSON-formatted requests from standard input
    /// instead of using command-line arguments. Useful for batch processing.
    #[arg(long)]
    json_input: bool,
}

/// Command-line operation argument wrapper
/// 
/// This enum wraps our library's `Operation` enum to work with clap's
/// argument parsing. The `#[derive(ValueEnum)]` allows clap to automatically
/// generate help text and validate command-line values.
/// 
/// We need this wrapper because we can't add clap derives to the library types
/// (that would make the library depend on clap, which CLI users might not want).
#[derive(Clone, ValueEnum)]
enum OperationArg {
    /// Reading or retrieving data
    Read,
    /// Creating new data  
    Create,
    /// Modifying existing data
    Update,
    /// Removing data
    Delete,
    /// Executing RPCs or actions
    Exec,
}

/// Convert CLI operation argument to library operation type
/// 
/// This `From` trait implementation allows automatic conversion between
/// the CLI enum and the library enum. Rust's type system ensures this
/// conversion is always safe and never fails.
impl From<OperationArg> for Operation {
    fn from(op: OperationArg) -> Self {
        match op {
            OperationArg::Read => Operation::Read,
            OperationArg::Create => Operation::Create,
            OperationArg::Update => Operation::Update,
            OperationArg::Delete => Operation::Delete,
            OperationArg::Exec => Operation::Exec,
        }
    }
}

/// Command-line context argument wrapper
/// 
/// This enum wraps our library's `RequestContext` enum to work with clap's
/// argument parsing. Similar to `OperationArg`, this allows CLI parsing
/// without making the library depend on clap.
#[derive(Clone, ValueEnum)]
enum ContextArg {
    /// NETCONF protocol access
    Netconf,
    /// Command-line interface access
    Cli,
    /// Web-based user interface access
    Webui,
}

/// Convert CLI context argument to library context type
/// 
/// This `From` trait implementation allows automatic conversion between
/// the CLI enum and the library enum.
impl From<ContextArg> for nacm_validator::RequestContext {
    fn from(ctx: ContextArg) -> Self {
        match ctx {
            ContextArg::Netconf => nacm_validator::RequestContext::NETCONF,
            ContextArg::Cli => nacm_validator::RequestContext::CLI,
            ContextArg::Webui => nacm_validator::RequestContext::WebUI,
        }
    }
}

/// Output format options for results
/// 
/// Controls how validation results are displayed to the user.
/// Each format serves different use cases and integration scenarios.
#[derive(Clone, ValueEnum)]
enum OutputFormat {
    /// Human-readable text output (default)
    /// Shows "PERMIT" or "DENY" with optional verbose details
    Text,
    /// Structured JSON output for programmatic processing
    /// Includes all request details and decision information  
    Json,
    /// Exit code only, no text output
    /// Perfect for shell scripting where you only care about success/failure
    ExitCode,
}

/// JSON request structure for batch processing
/// 
/// When using `--json-input` mode, requests are provided as JSON objects
/// with this structure. All fields are deserialized from the JSON payload.
/// 
/// Example JSON:
/// ```json
/// {
///   "user": "alice",
///   "module": "ietf-interfaces", 
///   "operation": "read",
///   "path": "/interfaces/interface[name='eth0']",
///   "context": "netconf",
///   "command": "show status"
/// }
/// ```
#[derive(Serialize, Deserialize)]
struct JsonRequest {
    /// Username making the request
    user: String,
    /// YANG module name (optional)
    module: Option<String>,
    /// RPC name (optional) 
    rpc: Option<String>,
    /// Operation type as string ("read", "create", etc.)
    operation: String,
    /// XPath or data path (optional)
    path: Option<String>,
    /// Request context as string ("netconf", "cli", "webui") (optional)
    context: Option<String>,
    /// Command being executed (optional)
    command: Option<String>,
}

/// JSON response structure for results
/// 
/// Used when outputting results in JSON format. Includes both the
/// access decision and all the request details for complete traceability.
#[derive(Serialize)]
struct JsonResult {
    /// Access decision: "permit" or "deny"
    decision: String,
    /// Original request details echoed back
    user: String,
    module: Option<String>,
    rpc: Option<String>,
    operation: String,
    path: Option<String>,
    /// Request context ("netconf", "cli", "webui")
    context: Option<String>,
    /// Command being executed
    command: Option<String>,
    /// Indicates whether the configuration was loaded successfully
    config_loaded: bool,
    /// Whether this decision should be logged (Tail-f ACM extension)
    should_log: bool,
}

/// Main entry point for the NACM validator CLI tool
/// 
/// This function orchestrates the entire validation process:
/// 1. Parse command-line arguments using clap
/// 2. Load and validate the NACM configuration file
/// 3. Route to appropriate handler based on input mode
/// 4. Set proper exit codes for shell script integration
/// 
/// ## Error Handling
/// 
/// The function uses Rust's standard error handling patterns:
/// - `Result<T, E>` for operations that can fail
/// - `process::exit()` with specific codes for different error types
/// - Graceful error messages to stderr
/// 
/// ## Exit Codes
/// - 0: Access permitted (success)
/// - 1: Access denied 
/// - 2: Configuration or runtime error
fn main() {
    // Parse command-line arguments
    // If parsing fails (invalid args), clap automatically shows help and exits
    let cli = Cli::parse();

    // Load NACM configuration from the specified file
    let config = match load_config(&cli.config) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Error loading config: {}", e);
            process::exit(2);  // Exit with error code 2 for configuration issues
        }
    };

    // Show configuration summary if verbose mode is enabled
    if cli.verbose {
        eprintln!("Loaded NACM config from: {:?}", cli.config);
        eprintln!("NACM enabled: {}", config.enable_nacm);
        eprintln!("Groups: {}", config.groups.len());
        eprintln!("Rule lists: {}", config.rule_lists.len());
    }

    // Route to appropriate handler based on input mode
    if cli.json_input {
        // Batch processing mode: read JSON requests from stdin
        handle_json_input(&config, &cli);
    } else {
        // Single request mode: use command-line arguments
        
        // Validate required arguments for single request mode
        // In JSON mode, these come from the JSON payload instead
        let user = match &cli.user {
            Some(u) => u,
            None => {
                eprintln!("Error: --user is required for single request mode");
                process::exit(2);
            }
        };
        let operation = match &cli.operation {
            Some(op) => op,
            None => {
                eprintln!("Error: --operation is required for single request mode");
                process::exit(2);
            }
        };
        
        // Process the single request and exit with appropriate code
        handle_single_request(&config, &cli, user, operation);
    }
}

/// Load and parse NACM configuration from file
/// 
/// This helper function encapsulates the file loading and XML parsing logic.
/// It provides a clean error boundary and consistent error handling.
/// 
/// ## Parameters
/// 
/// * `config_path` - Path to the NACM XML configuration file
/// 
/// ## Returns
/// 
/// * `Ok(NacmConfig)` - Successfully loaded and parsed configuration
/// * `Err(Box<dyn Error>)` - File not found, permission denied, invalid XML, etc.
/// 
/// ## Error Types
/// 
/// This function can return various error types:
/// - I/O errors (file not found, permission denied)
/// - XML parsing errors (malformed XML, unknown elements)
/// - NACM validation errors (invalid rule effects, unknown operations)
fn load_config(config_path: &PathBuf) -> Result<NacmConfig, Box<dyn std::error::Error>> {
    // Read the entire file into memory as a UTF-8 string
    // This will fail if the file doesn't exist or isn't readable
    let xml_content = std::fs::read_to_string(config_path)?;
    
    // Parse the XML content using our library's parsing function
    // This can fail for malformed XML or invalid NACM content
    NacmConfig::from_xml(&xml_content)
}

/// Handle single access request validation
/// 
/// This function processes a single access request using command-line arguments
/// and outputs the result according to the specified format. After displaying
/// results, it exits with an appropriate code for shell script integration.
/// 
/// ## Parameters
/// 
/// * `config` - Loaded NACM configuration
/// * `cli` - Parsed command-line arguments
/// * `user` - Username making the request (validated to be present)
/// * `operation` - Operation type (validated to be present)
/// 
/// ## Exit Codes
/// 
/// This function always calls `process::exit()`:
/// - Code 0: Access permitted
/// - Code 1: Access denied
fn handle_single_request(config: &NacmConfig, cli: &Cli, user: &str, operation: &OperationArg) {
    // Convert CLI operation argument to library operation type
    // This conversion is infallible (never panics) due to the From impl
    let operation = operation.clone().into();
    
    // Convert CLI context argument to library context type (if provided)
    let context = cli.context.as_ref().map(|ctx| ctx.clone().into());
    
    // Build the access request from command-line arguments
    // Uses borrowed string slices for efficiency (no copying)
    let request = AccessRequest {
        user,
        module_name: cli.module.as_deref(),    // Convert Option<String> to Option<&str>
        rpc_name: cli.rpc.as_deref(),
        operation,
        path: cli.path.as_deref(),
        context: context.as_ref(), // Convert Option<RequestContext> to Option<&RequestContext>
        command: cli.command.as_deref(), // Convert Option<String> to Option<&str>
    };

    // Perform the actual NACM validation using our library
    let result = config.validate(&request);
    
    // Output results in the requested format
    output_result(&result, &request, config, &cli.format, cli.verbose);
    
    // Set exit code based on access decision
    // This is crucial for shell script integration
    match result.effect {
        RuleEffect::Permit => process::exit(0),  // Success: access granted
        RuleEffect::Deny => process::exit(1),    // Failure: access denied
    }
}

/// Handle JSON input from stdin (streaming mode)
/// 
/// This function processes JSON requests line-by-line from standard input,
/// making it suitable for shell pipelines and streaming use cases. Each
/// line should contain a single JSON request object.
/// 
/// ## Input Format
/// 
/// Each line of stdin should be a complete JSON object:
/// ```json
/// {"user": "admin", "operation": "read", "module": "example"}
/// {"user": "operator", "operation": "execute", "rpc": "restart"}
/// ```
/// 
/// ## Output Format
/// 
/// For each valid input line, outputs a JSON result:
/// ```json
/// {"decision": "permit", "user": "admin", "operation": "read", ...}
/// {"decision": "deny", "user": "operator", "operation": "execute", ...}
/// ```
/// 
/// ## Error Handling
/// 
/// - Invalid JSON lines are logged to stderr but don't stop processing
/// - Invalid operations are logged and skipped
/// - I/O errors terminate the processing loop
/// 
/// ## Parameters
/// 
/// * `config` - Loaded NACM configuration for validation
/// * `cli` - Command-line arguments (mainly for format settings)
fn handle_json_input(config: &NacmConfig, _cli: &Cli) {
    use std::io::{self, BufRead};
    
    // Create a buffered reader from stdin for line-by-line processing
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        match line {
            Ok(json_str) => {
                // Try to parse each line as a JSON request
                match serde_json::from_str::<JsonRequest>(&json_str) {
                    Ok(json_req) => {
                        // Parse the operation string into our Operation enum
                        let operation = match json_req.operation.parse::<Operation>() {
                            Ok(op) => op,
                            Err(e) => {
                                eprintln!("Invalid operation '{}': {}", json_req.operation, e);
                                continue; // Skip this request and continue with next
                            }
                        };
                        
                        // Parse the context string into our RequestContext enum (if provided)
                        let context = match &json_req.context {
                            Some(ctx_str) => {
                                match ctx_str.to_lowercase().as_str() {
                                    "netconf" => Some(RequestContext::NETCONF),
                                    "cli" => Some(RequestContext::CLI),
                                    "webui" => Some(RequestContext::WebUI),
                                    _ => {
                                        eprintln!("Invalid context '{}': must be 'netconf', 'cli', or 'webui'", ctx_str);
                                        continue; // Skip this request and continue with next
                                    }
                                }
                            }
                            None => None,
                        };
                        
                        // Build the access request from JSON data
                        let request = AccessRequest {
                            user: &json_req.user,
                            module_name: json_req.module.as_deref(),
                            rpc_name: json_req.rpc.as_deref(),
                            operation,
                            path: json_req.path.as_deref(),
                            context: context.as_ref(), // Convert Option<RequestContext> to Option<&RequestContext>
                            command: json_req.command.as_deref(), // Convert Option<String> to Option<&str>
                        };

                        // Validate the request using NACM
                        let result = config.validate(&request);
                        
                        // Build JSON response with complete traceability
                        let json_result = JsonResult {
                            decision: match result.effect {
                                RuleEffect::Permit => "permit".to_string(),
                                RuleEffect::Deny => "deny".to_string(),
                            },
                            user: json_req.user,
                            module: json_req.module,
                            rpc: json_req.rpc,
                            operation: json_req.operation,
                            path: json_req.path,
                            context: json_req.context,
                            command: json_req.command,
                            config_loaded: true,
                            should_log: result.should_log,
                        };
                        
                        // Output result as compact JSON (one per line)
                        println!("{}", serde_json::to_string(&json_result).unwrap());
                    }
                    Err(e) => {
                        // Log JSON parsing errors but continue processing
                        eprintln!("Invalid JSON: {}", e);
                    }
                }
            }
            Err(e) => {
                // I/O errors are more serious - terminate processing
                eprintln!("Error reading input: {}", e);
                break;
            }
        }
    }
}

/// Output validation results in the requested format
/// 
/// This function handles the formatting and display of NACM validation results.
/// It supports multiple output formats for different use cases: human-readable
/// text for interactive use and JSON for programmatic consumption.
/// 
/// ## Output Formats
/// 
/// **Text Format** (default):
/// ```
/// Decision: PERMIT [LOGGED]
/// User: admin
/// Operation: read
/// Module: example-module
/// Context: cli
/// Command: show status
/// ```
/// 
/// **JSON Format**:
/// ```json
/// {
///   "decision": "permit", 
///   "user": "admin",
///   "operation": "read",
///   "module": "example-module",
///   "context": "cli",
///   "command": "show status",
///   "should_log": true
/// }
/// ```
/// 
/// ## Verbosity Levels
/// 
/// In verbose mode, additional information is displayed:
/// - Configuration statistics (groups, rules)
/// - Rule matching details
/// - NACM enforcement status
/// 
/// ## Parameters
/// 
/// * `result` - The validation result with access decision and logging flag
/// * `request` - Original access request details
/// * `config` - NACM configuration (for verbose output)
/// * `format` - Output format selection
/// * `verbose` - Whether to include additional details
fn output_result(
    result: &nacm_validator::ValidationResult,
    request: &AccessRequest,
    _config: &NacmConfig,
    format: &OutputFormat,
    verbose: bool,
) {
    match format {
        OutputFormat::Text => {
            // Human-readable text output
            let decision = match result.effect {
                RuleEffect::Permit => "PERMIT",
                RuleEffect::Deny => "DENY",
            };
            
            let log_indicator = if result.should_log { " [LOGGED]" } else { "" };
            
            // In verbose mode, show detailed request information
            if verbose {
                println!("User: {}", request.user);
                if let Some(module) = request.module_name {
                    println!("Module: {}", module);
                }
                if let Some(rpc) = request.rpc_name {
                    println!("RPC: {}", rpc);
                }
                println!("Operation: {:?}", request.operation);
                if let Some(path) = request.path {
                    println!("Path: {}", path);
                }
                if let Some(context) = request.context {
                    println!("Context: {:?}", context);
                }
                if let Some(command) = request.command {
                    println!("Command: {}", command);
                }
                println!("Decision: {}{}", decision, log_indicator);
            } else {
                // Simple mode: show decision with log indicator
                println!("{}{}", decision, log_indicator);
            }
        }
        OutputFormat::Json => {
            // Structured JSON output for programmatic consumption
            let json_result = JsonResult {
                decision: match result.effect {
                    RuleEffect::Permit => "permit".to_string(),
                    RuleEffect::Deny => "deny".to_string(),
                },
                user: request.user.to_string(),
                module: request.module_name.map(|s| s.to_string()),
                rpc: request.rpc_name.map(|s| s.to_string()),
                operation: format!("{:?}", request.operation).to_lowercase(),
                path: request.path.map(|s| s.to_string()),
                context: request.context.map(|ctx| format!("{:?}", ctx).to_lowercase()),
                command: request.command.map(|s| s.to_string()),
                config_loaded: true,
                should_log: result.should_log,
            };
            
            // Pretty-print JSON for readability
            println!("{}", serde_json::to_string_pretty(&json_result).unwrap());
        }
        OutputFormat::ExitCode => {
            // Silent mode: only use exit codes, no text output
            // This is useful for shell scripts that only care about success/failure
        }
    }
}
