/// Known-compromised axios versions: (major, minor, patch)
pub const COMPROMISED_AXIOS: &[(&str, &str, &str)] = &[("1", "14", "1"), ("0", "30", "4")];

/// Malicious packages injected by the attack
pub const MALICIOUS_PACKAGES: &[&str] = &["plain-crypto-js"];

/// Secondary distribution vectors
pub const SECONDARY_PACKAGES: &[&str] = &["@shadanai/openclaw", "@qqbrowser/openclaw-qbot"];

/// C2 infrastructure
pub const C2_DOMAIN: &str = "sfrclak.com";
pub const C2_IP: &str = "142.11.206.73";
pub const C2_PORT: u16 = 8000;

/// SHA-256 hashes of known malicious files
pub const HASH_SETUP_JS: &str =
    "e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09";
pub const HASHES_MACOS_RAT: &[&str] = &[
    "92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a",
];
pub const HASHES_WINDOWS_PS1: &[&str] = &[
    "ed8560c1ac7ceb6983ba995124d5917dc1a00288912387a6389296637d5f815c",
    "617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101",
];
pub const HASH_WINDOWS_BAT: &str =
    "e49c2732fb9861548208a78e72996b9c3c470b6b562576924bcc3a9fb75bf9ff";
pub const HASHES_LINUX_RAT: &[&str] = &[
    "6483c004e207137385f480909d6edecf1b699087378aa91745ecba7c3394f9d7",
    "fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf",
];

/// Suspicious install hook keywords
pub const SUSPICIOUS_HOOKS: &[&str] = &["postinstall", "preinstall", "install"];

/// Directories to skip during traversal
pub const SKIP_DIRS: &[&str] = &[
    ".git",
    ".hg",
    "System Volume Information",
    "$RECYCLE.BIN",
    "Windows",
];
