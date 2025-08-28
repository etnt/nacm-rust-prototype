# Internet Engineering Task Force (IETF)                      T. Tornkvist
# Internet-Draft                                           Tail-f Systems
# Intended status: Standards Track                            August 2025
# Expires: February 28, 2026

# Extensions to Network Configuration Access Control Model (NACM) for Command-Based Access Control

## Abstract

This document defines extensions to the Network Configuration Access Control
Model (NACM) as specified in RFC 8341. The extensions introduce command-based
access control capabilities that complement the existing data access control
mechanisms. These extensions are particularly relevant for network management
systems that provide command-line interfaces (CLI) and web-based user
interfaces (Web UI) in addition to NETCONF protocol access.

## Status of This Memo

This Internet-Draft is submitted in full conformance with the provisions of
BCP 78 and BCP 79.

Internet-Drafts are working documents of the Internet Engineering Task Force
(IETF). Note that other groups may also distribute working documents as
Internet-Drafts. The list of current Internet-Drafts is at
https://datatracker.ietf.org/drafts/current/.

Internet-Drafts are draft documents valid for a maximum of six months and may
be updated, replaced, or obsoleted by other documents at any time. It is
inappropriate to use Internet-Drafts as reference material or to cite them
other than as "work in progress."

This Internet-Draft will expire on February 28, 2026.

## Copyright Notice

Copyright (c) 2025 IETF Trust and the persons identified as the document
authors. All rights reserved.

This document is subject to BCP 78 and the IETF Trust's Legal Provisions
Relating to IETF Documents (https://trustee.ietf.org/license-info) in effect
on the date of publication of this document. Please review these documents
carefully, as they describe your rights and restrictions with respect to this
document. Code Components extracted from this document must include Simplified
BSD License text as described in Section 4.e of the Trust Legal Provisions
and are provided without warranty as described in the Simplified BSD License.

## Table of Contents

1. [Introduction](#1-introduction)
2. [Requirements Language](#2-requirements-language)
3. [Problem Statement](#3-problem-statement)
4. [Solution Overview](#4-solution-overview)
5. [YANG Module Description](#5-yang-module-description)
6. [Configuration Examples](#6-configuration-examples)
7. [Security Considerations](#7-security-considerations)
8. [IANA Considerations](#8-iana-considerations)
9. [References](#9-references)
10. [Appendix A: Complete YANG Module](#appendix-a-complete-yang-module)

## 1. Introduction

The Network Configuration Access Control Model (NACM) defined in RFC 8341
provides a comprehensive framework for controlling access to configuration and
state data in network devices. However, many network management systems
provide additional interfaces beyond NETCONF, such as command-line interfaces
(CLI) and web-based user interfaces (Web UI). These interfaces often expose
management operations that don't map directly to NETCONF operations on
configuration data.

This document defines extensions to NACM that provide:

1. Command-based access control rules for CLI and Web UI operations
2. Default access control policies for command operations
3. Enhanced logging capabilities for access control decisions
4. Group ID associations for operating system integration

The extensions are defined in the `tailf-acm` YANG module, which augments the
standard `ietf-netconf-acm` module defined in RFC 8341.

## 2. Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174]
when, and only when, they appear in all capitals, as shown here.

## 3. Problem Statement

While RFC 8341 provides excellent access control for NETCONF operations on
configuration and state data, network management systems typically provide
additional management interfaces that require access control:

### 3.1 Command-Line Interface (CLI) Operations

CLI operations often include:
- Administrative commands (e.g., system restart, log rotation)
- Diagnostic commands (e.g., ping, traceroute, show statistics)
- Maintenance operations (e.g., backup/restore, software upgrades)

These operations don't directly correspond to NETCONF operations on specific
data nodes and thus cannot be adequately controlled by standard NACM rules.

### 3.2 Web UI Operations

Web-based management interfaces provide graphical access to device management
functions. These operations may include:
- Dashboard views with aggregated information
- Wizard-based configuration workflows
- File upload/download operations

### 3.3 Operating System Integration

Network devices often need to integrate with operating system user and group
management, requiring:
- Mapping of NACM groups to OS group IDs
- Support for supplementary group memberships
- Process execution with appropriate group privileges

## 4. Solution Overview

The `tailf-acm` module extends RFC 8341 by adding:

### 4.1 Command Rules

Command rules (`cmdrule`) provide access control for CLI and Web UI operations.
Each rule specifies:
- **Context**: The management interface (cli, webui, etc.)
- **Command**: The specific command or operation pattern
- **Access Operations**: The type of access (read, exec)
- **Action**: Whether to permit or deny access

### 4.2 Default Policies for Commands

Two new default policy leaves extend the standard NACM defaults:
- `cmd-read-default`: Default action for command read operations
- `cmd-exec-default`: Default action for command execution operations

### 4.3 Enhanced Logging

Additional logging controls allow fine-grained control over access control
logging:
- `log-if-default-permit`: Log access granted by default policies
- `log-if-default-deny`: Log access denied by default policies
- `log-if-permit`: Log access granted by specific rules
- `log-if-deny`: Log access denied by specific rules

### 4.4 Group ID Mapping

The `gid` leaf associates numerical group IDs with NACM groups, enabling
integration with OS-level access controls.

## 5. YANG Module Description

### 5.1 Module Structure

The `tailf-acm` module uses YANG augmentation to extend the `ietf-netconf-acm`
module at several points:

```
augment /nacm:nacm:
  +--rw cmd-read-default?         nacm:action-type
  +--rw cmd-exec-default?         nacm:action-type
  +--rw log-if-default-permit?    empty
  +--rw log-if-default-deny?      empty

augment /nacm:nacm/nacm:groups/nacm:group:
  +--rw gid?  int32

augment /nacm:nacm/nacm:rule-list:
  +--rw cmdrule* [name]
     +--rw name                 string
     +--rw context?             union
     +--rw command?             string
     +--rw access-operations?   union
     +--rw action               nacm:action-type
     +--rw log-if-permit?       empty
     +--rw log-if-deny?         empty
     +--rw comment?             string

augment /nacm:nacm/nacm:rule-list/nacm:rule:
  +--rw context?         union
  +--rw log-if-permit?   empty
  +--rw log-if-deny?     empty
```

### 5.2 Command Rules

Command rules are processed in user-defined order until a match is found. A
rule matches when all of the following conditions are met:

1. **Context Match**: The `context` leaf matches the requesting agent (e.g.,
   'cli', 'webui') or is set to '*' (wildcard)
2. **Command Match**: The `command` leaf matches the requested command pattern
3. **Access Operations Match**: The `access-operations` leaf includes the
   requested operation type

When a rule matches, the `action` leaf determines whether access is granted or
denied.

### 5.3 Command Matching

Commands are represented as space-separated tokens. The matching algorithm
supports:
- Exact string matching
- Wildcard matching with '*'
- Prefix matching for command hierarchies

Examples:
- `"show interfaces"` - matches exactly "show interfaces"
- `"show *"` - matches any command starting with "show"
- `"*"` - matches any command

### 5.4 Access Operations

Command access operations include:
- **read**: Permission to read/view command output
- **exec**: Permission to execute/run the command

The `access-operations` leaf can specify:
- Specific operations: "read" or "exec"
- Multiple operations: "read exec"
- All operations: "*"

### 5.5 Default Policies

The module introduces two new default policy controls:

- `cmd-read-default`: Controls access when no matching command rule is found
  for read operations. Default value is "permit".
- `cmd-exec-default`: Controls access when no matching command rule is found
  for exec operations. Default value is "permit".

These defaults operate independently of the standard NACM defaults
(`read-default`, `write-default`, `exec-default`).

### 5.6 Logging Enhancements

Standard NACM implementations vary in their logging behavior. This module
provides comprehensive logging controls for both permit and deny decisions:

- `log-if-default-permit`: When present, logs access granted by default
  policies
- `log-if-default-deny`: When present, logs access denied by default policies
- `log-if-permit`: When present on a rule, logs access granted by that specific
  rule
- `log-if-deny`: When present on a rule, logs access denied by that specific
  rule

These logging enhancements provide several benefits:
- **Symmetric Control**: Both permit and deny actions can be logged consistently
- **Debugging Capabilities**: Fine-grained control over what gets logged
- **Auditing Support**: Complete access control audit trails when needed
- **Performance Optimization**: Logging can be disabled for high-frequency
  operations to reduce log volume

The absence of these leaves means that logging behavior follows implementation
defaults, providing backward compatibility while allowing administrators to
opt-in to more detailed logging as needed.

### 5.7 Group ID Mapping

The `gid` leaf associates a numerical group ID with each NACM group. This
enables:
- Integration with OS-level access controls
- Setting supplementary group IDs for executed processes
- Consistent group-based permissions across management interfaces

## 6. Configuration Examples

This section provides practical examples of how to configure command rules
using the `tailf-acm` extensions. The examples demonstrate various scenarios
common in network device management.

### 6.1 Basic Command Access Control

The following example shows basic command rules for different user groups:

```xml
<nacm xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-acm">
  <enable-nacm>true</enable-nacm>
  <cmd-read-default xmlns="http://tail-f.com/yang/acm">deny</cmd-read-default>
  <cmd-exec-default xmlns="http://tail-f.com/yang/acm">deny</cmd-exec-default>
  <log-if-default-permit xmlns="http://tail-f.com/yang/acm"/>
  <log-if-default-deny xmlns="http://tail-f.com/yang/acm"/>

  <rule-list>
    <name>operators</name>
    <group>oper</group>

    <!-- Allow operators to view system status -->
    <cmdrule xmlns="http://tail-f.com/yang/acm">
      <name>cli-show-status</name>
      <context>cli</context>
      <command>show status</command>
      <access-operations>read exec</access-operations>
      <action>permit</action>
      <log-if-permit/>
    </cmdrule>

    <!-- Allow help command -->
    <cmdrule xmlns="http://tail-f.com/yang/acm">
      <name>cli-help</name>
      <context>cli</context>
      <command>help</command>
      <action>permit</action>
      <log-if-permit/>
    </cmdrule>

    <!-- Deny system logout for operators -->
    <cmdrule xmlns="http://tail-f.com/yang/acm">
      <name>cli-request-system-logout</name>
      <context>cli</context>
      <command>request system logout</command>
      <action>deny</action>
      <log-if-deny/>
    </cmdrule>

  </rule-list>
</nacm>
```

### 6.2 Hierarchical Command Matching

This example demonstrates how command patterns can match hierarchically:

```xml
<rule-list>
  <name>limited-admin</name>
  <group>limited-admin</group>

  <!-- Allow specific system message command -->
  <cmdrule xmlns="http://tail-f.com/yang/acm">
    <name>cli-request-system-message</name>
    <context>cli</context>
    <command>request system message</command>
    <action>permit</action>
    <log-if-permit/>
  </cmdrule>

  <!-- Deny all other system request commands -->
  <cmdrule xmlns="http://tail-f.com/yang/acm">
    <name>cli-request-system</name>
    <context>cli</context>
    <command>request system</command>
    <action>deny</action>
    <log-if-deny/>
  </cmdrule>

</rule-list>
```

In this example, the rule processing order is critical. The more specific
"request system message" rule is processed first and permits access. The
broader "request system" rule would deny access to other system request
commands like "request system reboot".

### 6.3 Multi-Context Access Control

Commands can be controlled across different management interfaces:

```xml
<rule-list>
  <name>admin</name>
  <group>admin</group>

  <!-- Allow all commands from any context for administrators -->
  <cmdrule xmlns="http://tail-f.com/yang/acm">
    <name>any-command</name>
    <context>*</context>
    <command>*</command>
    <access-operations>*</access-operations>
    <action>permit</action>
    <log-if-permit/>
  </cmdrule>

</rule-list>
```

### 6.4 Context-Specific Rules

Different rules can apply based on the management interface:

```xml
<rule-list>
  <name>context-specific</name>
  <group>users</group>

  <!-- Allow diagnostic commands only from CLI -->
  <cmdrule xmlns="http://tail-f.com/yang/acm">
    <name>cli-diagnostics</name>
    <context>cli</context>
    <command>show diagnostics</command>
    <access-operations>read</access-operations>
    <action>permit</action>
  </cmdrule>

  <!-- Allow configuration viewing from Web UI -->
  <cmdrule xmlns="http://tail-f.com/yang/acm">
    <name>webui-config-view</name>
    <context>webui</context>
    <command>view configuration</command>
    <access-operations>read</access-operations>
    <action>permit</action>
  </cmdrule>

  <!-- Deny configuration changes from all contexts -->
  <cmdrule xmlns="http://tail-f.com/yang/acm">
    <name>deny-config-changes</name>
    <context>*</context>
    <command>configure</command>
    <access-operations>exec</access-operations>
    <action>deny</action>
    <log-if-deny/>
  </cmdrule>

</rule-list>
```

### 6.5 Integration with Standard NACM Rules

Command rules work alongside standard NACM data access rules:

```xml
<rule-list>
  <name>mixed-permissions</name>
  <group>mixed-users</group>

  <!-- Standard NACM rule for data access -->
  <rule>
    <name>system-interfaces-read</name>
    <module-name>system</module-name>
    <path>/system/interfaces</path>
    <access-operations>read</access-operations>
    <action>permit</action>
    <context xmlns="http://tail-f.com/yang/acm">netconf</context>
  </rule>

  <!-- Command rule for CLI access to interface status -->
  <cmdrule xmlns="http://tail-f.com/yang/acm">
    <name>cli-show-interfaces</name>
    <context>cli</context>
    <command>show interfaces</command>
    <access-operations>read</access-operations>
    <action>permit</action>
  </cmdrule>

  <!-- Command rule denying interface configuration via CLI -->
  <cmdrule xmlns="http://tail-f.com/yang/acm">
    <name>cli-configure-interfaces</name>
    <context>cli</context>
    <command>configure interfaces</command>
    <access-operations>exec</access-operations>
    <action>deny</action>
    <log-if-deny/>
  </cmdrule>

</rule-list>
```

### 6.6 Default Policy Configuration

Setting restrictive defaults with specific permissions:

```xml
<nacm xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-acm">
  <!-- Set restrictive defaults -->
  <read-default>deny</read-default>
  <write-default>deny</write-default>
  <exec-default>deny</exec-default>
  <cmd-read-default xmlns="http://tail-f.com/yang/acm">deny</cmd-read-default>
  <cmd-exec-default xmlns="http://tail-f.com/yang/acm">deny</cmd-exec-default>
  
  <!-- Enable logging for both default permit and deny actions -->
  <log-if-default-permit xmlns="http://tail-f.com/yang/acm"/>
  <log-if-default-deny xmlns="http://tail-f.com/yang/acm"/>

  <rule-list>
    <name>secure-operators</name>
    <group>secure-oper</group>

    <!-- Explicitly permit only necessary operations -->
    <cmdrule xmlns="http://tail-f.com/yang/acm">
      <name>essential-commands</name>
      <context>cli</context>
      <command>show system status</command>
      <access-operations>read</access-operations>
      <action>permit</action>
      <comment>Essential system monitoring for operators</comment>
    </cmdrule>

  </rule-list>
</nacm>
```

## 7. Security Considerations

### 7.1 Command Injection

Implementations MUST carefully validate and sanitize command patterns to
prevent command injection attacks. Command matching should be performed against
a controlled vocabulary of allowed commands.

### 7.2 Privilege Escalation

The `gid` mapping feature introduces potential privilege escalation risks.
Implementations MUST:
- Validate that assigned group IDs are appropriate for the user's privilege
  level
- Prevent assignment of system or administrative group IDs to unprivileged
  users
- Audit group ID assignments regularly

### 7.3 Information Disclosure

Command read operations may expose sensitive system information. Access control
rules should be carefully designed to prevent unauthorized information
disclosure through command output.

### 7.4 Logging Sensitivity

Enhanced logging may record sensitive information in log files.
Implementations SHOULD:
- Protect log files with appropriate file system permissions
- Consider log rotation and retention policies
- Sanitize sensitive information from log entries when possible

The symmetric logging controls (`log-if-permit`, `log-if-deny`, 
`log-if-default-permit`, `log-if-default-deny`) provide administrators with
fine-grained control over logging behavior. However, this also means that:
- Administrators must carefully consider which access decisions to log
- Excessive logging may impact system performance
- Log volume can become substantial in high-traffic environments
- Both successful and failed access attempts may reveal system usage patterns

Implementations SHOULD provide guidance on appropriate logging strategies for
different operational environments.

### 7.5 Default Policies

The default "permit" behavior for command operations follows the principle of
maintaining backward compatibility but may be overly permissive for some
environments. Administrators SHOULD:
- Review and adjust default policies based on security requirements
- Implement explicit deny rules for sensitive operations
- Regular audit command access patterns

## 8. IANA Considerations

This document registers the following YANG module in the YANG Module Names
registry [RFC6020]:

```
Name:         tailf-acm
Namespace:    http://tail-f.com/yang/acm
Prefix:       tacm
Reference:    RFC XXXX
```

## 9. References

### 9.1 Normative References

[RFC2119]  Bradner, S., "Key words for use in RFCs to Indicate Requirement
           Levels", BCP 14, RFC 2119, DOI 10.17487/RFC2119, March 1997,
           <https://www.rfc-editor.org/info/rfc2119>.

[RFC6020]  Bjorklund, M., Ed., "YANG - A Data Modeling Language for the
           Network Configuration Protocol (NETCONF)", RFC 6020,
           DOI 10.17487/RFC6020, October 2010,
           <https://www.rfc-editor.org/info/rfc6020>.

[RFC8174]  Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key
           Words", BCP 14, RFC 8174, DOI 10.17487/RFC8174, May 2017,
           <https://www.rfc-editor.org/info/rfc8174>.

[RFC8341]  Bierman, A. and M. Bjorklund, "Network Configuration Access
           Control Model", STD 91, RFC 8341, DOI 10.17487/RFC8341,
           March 2018, <https://www.rfc-editor.org/info/rfc8341>.

### 9.2 Informative References

[RFC6241]  Enns, R., Ed., Bjorklund, M., Ed., Schoenwaelder, J., Ed., and A.
           Bierman, Ed., "Network Configuration Protocol (NETCONF)",
           RFC 6241, DOI 10.17487/RFC6241, June 2011,
           <https://www.rfc-editor.org/info/rfc6241>.

## Appendix A: Complete YANG Module

```yang
module tailf-acm {
  namespace "http://tail-f.com/yang/acm";
  prefix tacm;

  import ietf-netconf-acm {
    prefix nacm;
  }

  organization "Tail-f Systems";

  description
    "This module augments ietf-netconf-acm with additional
     access control data.

     Copyright 2012-2013 Cisco Systems, Inc.
     All rights reserved.
     Permission is hereby granted to redistribute this file without
     modification.";

  revision 2013-03-07 {
    description
      "Released as part of ConfD-4.2.

       Added cmd-read-default and cmd-exec-default.";
  }

  revision 2012-11-08 {
    description
      "Initial revision.

       Released as part of ConfD-4.1.";
  }

  augment /nacm:nacm {
    leaf cmd-read-default {
      type nacm:action-type;
      default "permit";
      description
        "Controls whether command read access is granted
         if no appropriate cmdrule is found for a
         particular command read request.";
    }

    leaf cmd-exec-default {
      type nacm:action-type;
      default "permit";
      description
        "Controls whether command exec access is granted
         if no appropriate cmdrule is found for a
         particular command exec request.";
    }

    leaf log-if-default-permit {
      type empty;
      description
        "If this leaf is present, access granted due to one of
         /nacm/read-default, /nacm/write-default, /nacm/exec-default
         /nacm/cmd-read-default, or /nacm/cmd-exec-default
         being set to 'permit' is logged.";
    }

    leaf log-if-default-deny {
      type empty;
      description
        "If this leaf is present, access denied due to one of
         /nacm/read-default, /nacm/write-default, /nacm/exec-default
         /nacm/cmd-read-default, or /nacm/cmd-exec-default
         being set to 'deny' is logged.";
    }
  }

  augment /nacm:nacm/nacm:groups/nacm:group {
    leaf gid {
      type int32;
      description
        "This leaf associates a numerical group ID with the group.
         When a OS command is executed on behalf of a user,
         supplementary group IDs are assigned based on 'gid' values
         for the groups that the use is a member of.";
    }
  }

  augment /nacm:nacm/nacm:rule-list {

    list cmdrule {
      key "name";
      ordered-by user;
      description
        "One command access control rule. Command rules control access
         to CLI commands and Web UI functions.

         Rules are processed in user-defined order until a match is
         found.  A rule matches if 'context', 'command', and
         'access-operations' match the request.  If a rule
         matches, the 'action' leaf determines if access is granted
         or not.";

      leaf name {
        type string {
          length "1..max";
        }
        description
          "Arbitrary name assigned to the rule.";
      }

      leaf context {
        type union {
          type nacm:matchall-string-type;
          type string;
        }
        default "*";
        description
          "This leaf matches if it has the value '*' or if its value
           identifies the agent that is requesting access, i.e. 'cli'
           for CLI or 'webui' for Web UI.";
      }

      leaf command {
        type string;
        default "*";
        description
          "Space-separated tokens representing the command. Refer
           to the Tail-f AAA documentation for further details.";
      }

      leaf access-operations {
        type union {
          type nacm:matchall-string-type;
          type nacm:access-operations-type;
        }
        default "*";
        description
          "Access operations associated with this rule.

           This leaf matches if it has the value '*' or if the
           bit corresponding to the requested operation is set.";
      }

      leaf action {
        type nacm:action-type;
        mandatory true;
        description
          "The access control action associated with the
           rule.  If a rule is determined to match a
           particular request, then this object is used
           to determine whether to permit or deny the
           request.";
      }

      leaf log-if-permit {
        type empty;
        description
          "If this leaf is present, access granted due to this rule
           is logged.";
      }

      leaf log-if-deny {
        type empty;
        description
          "If this leaf is present, access denied due to this rule
           is logged.";
      }

      leaf comment {
        type string;
        description
          "A textual description of the access rule.";
      }
    }
  }

  augment /nacm:nacm/nacm:rule-list/nacm:rule {

    leaf context {
      type union {
        type nacm:matchall-string-type;
        type string;
      }
      default "*";
      description
        "This leaf matches if it has the value '*' or if its value
         identifies the agent that is requesting access, e.g. 'netconf'
         for NETCONF, 'cli' for CLI, or 'webui' for Web UI.";

    }

    leaf log-if-permit {
      type empty;
      description
        "If this leaf is present, access granted due to this rule
         is logged. Mainly intended for debugging of rules.";
    }

    leaf log-if-deny {
      type empty;
      description
        "If this leaf is present, access denied due to this rule
         is logged. This provides symmetric logging control with 
         log-if-permit for standard NACM rules.";
    }
  }
}
```

---

**Author's Address**

```
Torbjörn Tornkvist
Tail-f Systems
Email: ttornkvi@cisco.com
```
