//! On-demand, ephemeral remote-box lifecycle for the dynamic stages — `dynamic-windows` needs
//! a live Windows box, `dynamic-mac` needs a live Mac, and whichever one ISN'T the SASF host's
//! own OS genuinely can't be run natively. Frida attach, anti-debug bypass, and DLL/dylib
//! injection need a real OS process, not an emulation layer. Rather than requiring the analyst
//! to keep a box running as a 24/7 service, this shells out to an analyst-provided script right
//! before the relevant dynamic stage and tears it down right after — the script owns all
//! backend-specific detail (local VMware/VirtualBox, a cloud instance, a physical machine that's
//! always on, a Tailscale-reachable box, anything). sasf itself never talks to a hypervisor,
//! cloud API, or VPN directly, so any backend works without a code change here. See
//! `scripts/win-vm-*.sh.example` and `scripts/mac-box-*.sh.example` for reference
//! implementations, and the sasf-web "Remote Box" page for a connector-script generator.
//!
//! IMPORTANT — architecture fidelity:
//! - An Apple Silicon Mac can only locally virtualize ARM64 Windows, which runs x64 binaries
//!   through an emulation layer (Prism/WOW64) — fine for static work, but `dynamic-windows`
//!   exists to test precise anti-debug/anti-tamper behavior (hardware breakpoints, timing,
//!   `NtQueryInformationProcess` checks) that an emulation layer can subtly change. A real x64
//!   box (an Intel Mac's VM, or a small cloud Windows VM billed only while running) is the
//!   fidelity-preserving choice; local ARM64 Windows is a fallback of last resort.
//! - macOS virtualization is restricted by Apple's license to Apple-branded hardware — a
//!   Windows/Linux host analyzing a Mac target cannot spin up a "Mac VM" locally at all. The
//!   only real options are a physical Mac reachable over the network (a Mac mini is the cheap,
//!   common choice) or a cloud Mac (AWS EC2 Mac instances, MacStadium, Scaleway) — the latter
//!   bills in **24-hour minimum increments** by Apple's own dedicated-host licensing terms, so
//!   the "start before, kill after" cost savings this module gives Windows/cloud backends does
//!   NOT apply the same way to a cloud Mac; a persistent physical Mac is usually cheaper.

use std::path::PathBuf;

#[derive(Debug, Clone, Default)]
pub struct RemoteBox {
    pub host: String,
    pub user: String,
    pub pass: String,
}

/// Runs `<script> start`, which MUST print exactly one line to stdout on success:
///   `HOST=<ip-or-hostname> USER=<username> PASS=<password>`
/// (order doesn't matter, unrecognized keys ignored). Everything else on stdout/stderr is
/// treated as progress/diagnostic output, not parsed. This call blocks until the script
/// returns — a real VM/cloud boot takes anywhere from ~10s (a warm local VM) to a few minutes
/// (a cold cloud instance) or is instant (an always-on physical box) — the SCRIPT is
/// responsible for polling until genuinely reachable (frida-server actually listening, not
/// just "OS booted") before it prints the `HOST=` line. Returns `Ok(None)` when `script` is
/// `None` — the calling stage then runs exactly as before this feature existed (each dynamic
/// agent's own manual-setup fallback guidance). `label` is only used in log/error messages
/// ("win-vm" / "mac-box") so start/stop failures for the two stages aren't ambiguous in a log
/// where both could in principle appear.
pub fn start(script: &Option<PathBuf>, label: &str) -> anyhow::Result<Option<RemoteBox>> {
    let Some(script) = script else { return Ok(None) };
    println!("[{label}] starting via {}...", script.display());
    let out = std::process::Command::new(script).arg("start").output()?;
    if !out.status.success() {
        anyhow::bail!(
            "{label} start script exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut b = RemoteBox::default();
    for token in stdout.split_whitespace() {
        if let Some((k, v)) = token.split_once('=') {
            match k.to_ascii_uppercase().as_str() {
                "HOST" => b.host = v.to_string(),
                "USER" => b.user = v.to_string(),
                "PASS" => b.pass = v.to_string(),
                _ => {}
            }
        }
    }
    if b.host.is_empty() {
        anyhow::bail!("{label} start script produced no HOST=<ip> line — got: {}", stdout.trim());
    }
    println!("[{label}] up — host={}", b.host);
    Ok(Some(b))
}

/// Runs `<script> stop` — best-effort. A failure here is logged loudly but never fails the
/// analysis session: the findings already gathered matter more than a clean teardown, and an
/// analyst can always stop a stuck VM/instance by hand (this is exactly why the reference
/// scripts print the instance/VM name on every action — nothing is a mystery to clean up). A
/// physical-box script's `stop` is typically a deliberate no-op (see `scripts/mac-box-
/// physical.sh.example`) — this framework never powers off shared hardware on its own.
pub fn stop(script: &Option<PathBuf>, label: &str) {
    let Some(script) = script else { return };
    println!("[{label}] stopping via {}...", script.display());
    match std::process::Command::new(script).arg("stop").output() {
        Ok(out) if out.status.success() => println!("[{label}] stopped"),
        Ok(out) => eprintln!(
            "[{label}] ⚠ stop script exited {} — stop it by hand if still running: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ),
        Err(e) => eprintln!("[{label}] ⚠ failed to run stop script: {e} — stop it by hand if still running"),
    }
}

impl RemoteBox {
    /// Rendered as extra task-prompt context for the dynamic agent — same role as
    /// `context_summary()`'s prior-findings block, just carrying box connection info instead of
    /// findings. `os_label` is "Windows" or "macOS" (controls the wording only — the
    /// HOST/USER/PASS line and Frida command are identical either way). Explicitly tells the
    /// agent NOT to fall back to a hardcoded alias its own system prompt might mention, since
    /// that alias is a manual-setup assumption this mechanism replaces.
    pub fn context_block(&self, os_label: &str) -> String {
        format!(
            "\n\n## {os_label} box (ephemeral — booted just for this stage, torn down right after)\n\
             HOST={host} USER={user} PASS={pass}\n\
             frida-server should already be listening — attach with `frida -H {host}:27042 -p <PID>`. \
             Use the given user/pass over SSH (or WinRM on Windows) for file transfer and remote \
             exec. This box's address is only known at runtime — do NOT assume any hardcoded alias \
             (e.g. `ssh win-box`/`ssh mac-box`) exists.",
            host = self.host, user = self.user, pass = self.pass
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_block_includes_host_frida_command_and_os_label() {
        let b = RemoteBox { host: "10.0.0.5".into(), user: "analyst".into(), pass: "hunter2".into() };
        let ctx = b.context_block("Windows");
        assert!(ctx.contains("## Windows box"));
        assert!(ctx.contains("HOST=10.0.0.5"));
        assert!(ctx.contains("frida -H 10.0.0.5:27042"));
        assert!(ctx.contains("hunter2"));
    }

    #[test]
    fn start_returns_none_when_unconfigured() {
        assert!(start(&None, "win-vm").unwrap().is_none());
    }

    #[test]
    fn start_parses_host_user_pass_from_script_stdout() {
        let script = std::env::temp_dir().join(format!("sasf-remotebox-test-{}.sh", std::process::id()));
        std::fs::write(&script, "#!/bin/sh\necho 'HOST=10.1.2.3 USER=admin PASS=s3cr3t'\n").unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755)).ok();
        let b = start(&Some(script.clone()), "mac-box").unwrap().expect("should parse a RemoteBox");
        assert_eq!(b.host, "10.1.2.3");
        assert_eq!(b.user, "admin");
        assert_eq!(b.pass, "s3cr3t");
        std::fs::remove_file(&script).ok();
    }

    #[test]
    fn start_errors_when_no_host_line_printed() {
        let script = std::env::temp_dir().join(format!("sasf-remotebox-test-nohost-{}.sh", std::process::id()));
        std::fs::write(&script, "#!/bin/sh\necho 'booting...'\n").unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755)).ok();
        assert!(start(&Some(script.clone()), "win-vm").is_err());
        std::fs::remove_file(&script).ok();
    }
}
