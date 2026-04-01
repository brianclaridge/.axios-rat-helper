use crate::report::Finding;
use winreg::enums::HKEY_CURRENT_USER;
use winreg::RegKey;

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

/// Suspicious value substrings in registry Run key.
const SUSPECT_VALUES: &[&str] = &["system.bat", "wt.exe", "microsoftupdate"];

/// Check the Windows registry for persistence mechanisms planted by the RAT.
pub fn scan(findings: &mut Vec<Finding>) {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let run_key = match hkcu.open_subkey_with_flags(RUN_KEY, winreg::enums::KEY_READ) {
        Ok(k) => k,
        Err(_) => return,
    };

    for value in run_key.enum_values().flatten() {
        let (name, data) = (value.0, format!("{:?}", value.1));
        let data_lower = data.to_lowercase();
        for suspect in SUSPECT_VALUES {
            if data_lower.contains(suspect) {
                findings.push(Finding::critical(
                    "registry-persistence",
                    &format!("HKCU\\{RUN_KEY}\\{name}"),
                    &format!("Registry Run key references '{suspect}': {data}"),
                ));
            }
        }
    }
}
