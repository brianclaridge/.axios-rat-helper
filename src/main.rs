mod iocs;
mod report;
mod scanner;

use clap::Parser;
use report::Finding;
use std::path::PathBuf;
use std::time::Instant;

#[derive(Parser)]
#[command(
    name = "axios-rat-scan",
    about = "Scan for the axios supply chain RAT (2026-03-31)",
    version
)]
struct Cli {
    /// Directories to scan (default: all mounted drives)
    paths: Vec<PathBuf>,

    /// Output findings as JSON
    #[arg(long)]
    json: bool,

    /// Stop after the first CRITICAL finding
    #[arg(long)]
    fast: bool,

    /// Skip process and network checks (filesystem only)
    #[arg(long)]
    no_process: bool,

    /// Hide the project tree view
    #[arg(long)]
    no_tree: bool,

    /// Path to write npm_sources_map.yml (default: ./npm_sources_map.yml)
    #[arg(long, default_value = "npm_sources_map.yml")]
    sources_map: PathBuf,
}

/// Enumerate all mounted drives/volumes for the current platform.
fn enumerate_drives() -> Vec<PathBuf> {
    let mut drives = Vec::new();

    #[cfg(windows)]
    {
        for letter in b'A'..=b'Z' {
            let path = format!("{}:\\", letter as char);
            let p = PathBuf::from(&path);
            if p.exists() {
                drives.push(p);
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        drives.push(PathBuf::from("/"));
        if let Ok(entries) = std::fs::read_dir("/Volumes") {
            for entry in entries.flatten() {
                drives.push(entry.path());
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(mounts) = std::fs::read_to_string("/proc/mounts") {
            let skip_fs = [
                "proc", "sysfs", "devtmpfs", "tmpfs", "devpts", "cgroup",
                "cgroup2", "pstore", "securityfs", "debugfs", "hugetlbfs",
                "mqueue", "fusectl", "configfs", "binfmt_misc", "autofs",
                "efivarfs", "tracefs", "bpf", "overlay",
            ];
            for line in mounts.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    let mount_point = parts[1];
                    let fs_type = parts[2];
                    if !skip_fs.contains(&fs_type) {
                        drives.push(PathBuf::from(mount_point));
                    }
                }
            }
        }
        if drives.is_empty() {
            drives.push(PathBuf::from("/"));
        }
    }

    drives
}

fn main() {
    let cli = Cli::parse();
    let start = Instant::now();

    let roots = if cli.paths.is_empty() {
        let drives = enumerate_drives();
        eprintln!(
            "Scanning {} drive(s): {}",
            drives.len(),
            drives
                .iter()
                .map(|d| d.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
        drives
    } else {
        cli.paths.clone()
    };

    let mut findings: Vec<Finding> = Vec::new();

    // Host-level scans (fast, run first)
    scanner::filesystem::scan(&mut findings);

    #[cfg(windows)]
    scanner::registry::scan(&mut findings);

    if !cli.no_process {
        scanner::process::scan(&mut findings);
        scanner::network::scan(&mut findings);
    }

    // Early exit if --fast and we already have criticals
    if cli.fast && findings.iter().any(|f| f.severity == report::Severity::Critical) {
        let elapsed = start.elapsed();
        if cli.json {
            println!("{}", serde_json::to_string_pretty(&findings).unwrap());
        } else {
            report::print_summary(&findings, elapsed);
        }
        std::process::exit(1);
    }

    // Phase 1: Discover all npm projects
    eprintln!("Discovering npm projects...");
    let targets = scanner::npm::discover(&roots);

    eprintln!(
        "Found {} npm project(s), writing sources map to {}",
        targets.npm_sources.len(),
        cli.sources_map.display(),
    );
    scanner::npm::write_sources_map(&targets, &cli.sources_map);

    // Show the tree of discovered projects before scanning
    if !cli.no_tree && !cli.json {
        report::print_tree(&targets, &[]);
    }

    // Phase 2: Scan all discovered targets
    eprintln!("\nScanning for IOCs...");
    let npm_findings = scanner::npm::scan_targets(&targets);
    findings.extend(npm_findings);

    let elapsed = start.elapsed();

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&findings).unwrap());
        let has_critical = findings.iter().any(|f| f.severity == report::Severity::Critical);
        std::process::exit(if has_critical { 1 } else { 0 });
    }

    report::print_summary(&findings, elapsed);
    let has_critical = findings.iter().any(|f| f.severity == report::Severity::Critical);
    std::process::exit(if has_critical { 1 } else { 0 });
}
