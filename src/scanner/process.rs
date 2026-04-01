use crate::report::Finding;
use sysinfo::System;

/// Check running processes for signs of active RAT execution.
pub fn scan(findings: &mut Vec<Finding>) {
    let mut sys = System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

    for (pid, process) in sys.processes() {
        let name = process.name().to_string_lossy().to_lowercase();
        let cmd: Vec<String> = process.cmd().iter().map(|s| s.to_string_lossy().to_string()).collect();
        let cmd_joined = cmd.join(" ").to_lowercase();
        let exe_path = process
            .exe()
            .map(|p| p.display().to_string())
            .unwrap_or_default();

        // Windows: wt.exe running from ProgramData (renamed PowerShell)
        #[cfg(windows)]
        if name == "wt.exe" {
            let programdata =
                std::env::var("PROGRAMDATA").unwrap_or_else(|_| r"C:\ProgramData".into());
            if exe_path.to_lowercase().contains(&programdata.to_lowercase()) {
                findings.push(Finding::critical(
                    "active-rat-process",
                    &format!("PID {pid} ({exe_path})"),
                    "wt.exe running from ProgramData (likely renamed PowerShell RAT)",
                ));
            }
        }

        // macOS: com.apple.act.mond
        #[cfg(target_os = "macos")]
        if name == "com.apple.act.mond"
            || exe_path.contains("com.apple.act.mond")
        {
            findings.push(Finding::critical(
                "active-rat-process",
                &format!("PID {pid} ({exe_path})"),
                "com.apple.act.mond RAT process running",
            ));
        }

        // Linux: python running /tmp/ld.py
        #[cfg(target_os = "linux")]
        if (name.starts_with("python") || name == "python3")
            && cmd_joined.contains("/tmp/ld.py")
        {
            findings.push(Finding::critical(
                "active-rat-process",
                &format!("PID {pid} ({exe_path})"),
                "Python process running /tmp/ld.py RAT",
            ));
        }

        // Cross-platform: spoofed IE8 user-agent in any process command line
        if cmd_joined.contains("msie 8.0") && cmd_joined.contains("windows nt 5.1") {
            findings.push(Finding::critical(
                "c2-user-agent",
                &format!("PID {pid} ({exe_path})"),
                "Process command line contains spoofed IE8/WinXP User-Agent (C2 beacon indicator)",
            ));
        }
    }
}
