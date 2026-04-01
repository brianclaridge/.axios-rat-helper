use crate::iocs;
use crate::report::Finding;
use std::process::Command;

/// Parse netstat output for connections to the known C2 infrastructure.
pub fn scan(findings: &mut Vec<Finding>) {
    let output = if cfg!(windows) {
        Command::new("netstat").args(["-n", "-o"]).output()
    } else {
        Command::new("netstat").args(["-tnp"]).output()
    };

    let output = match output {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(_) => {
            // netstat may not be available — try ss on Linux
            if cfg!(target_os = "linux") {
                match Command::new("ss").args(["-tnp"]).output() {
                    Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
                    Err(_) => return,
                }
            } else {
                return;
            }
        }
    };

    for line in output.lines() {
        let lower = line.to_lowercase();
        // Check for C2 IP
        if lower.contains(iocs::C2_IP) {
            findings.push(Finding::critical(
                "active-c2-connection",
                "network",
                &format!("Active connection to C2 IP {}: {}", iocs::C2_IP, line.trim()),
            ));
        }
        // Check for C2 domain (in case resolved hostname shows up)
        if lower.contains(iocs::C2_DOMAIN) {
            findings.push(Finding::critical(
                "active-c2-connection",
                "network",
                &format!("Active connection to C2 domain {}: {}", iocs::C2_DOMAIN, line.trim()),
            ));
        }
        // Check for C2 port on the known IP
        let c2_endpoint = format!("{}:{}", iocs::C2_IP, iocs::C2_PORT);
        if lower.contains(&c2_endpoint) {
            findings.push(Finding::critical(
                "active-c2-connection",
                "network",
                &format!("Active connection to C2 endpoint {c2_endpoint}: {}", line.trim()),
            ));
        }
    }
}
