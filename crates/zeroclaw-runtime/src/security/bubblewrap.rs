//! Bubblewrap sandbox (user namespaces for Linux/macOS)

use crate::security::{detect::SandboxExtraRoots, traits::Sandbox};
use std::ffi::{OsStr, OsString};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use zeroclaw_config::platform::resolve_executable;

const CAPABILITY_DROPS: &[&str] = &["CAP_SYS_ADMIN", "CAP_SYS_PTRACE"];

#[derive(Debug, Clone, Copy, Default)]
struct BubblewrapHardeningSupport {
    cap_drop: bool,
}

/// Bubblewrap sandbox backend
#[derive(Debug, Clone, Default)]
pub struct BubblewrapSandbox {
    // These are construction inputs from the resolved per-agent policy. Paths
    // are validated again for every invocation, rather than caching live grants.
    workspace: Option<PathBuf>,
    extra_roots: SandboxExtraRoots,
}

impl BubblewrapSandbox {
    pub fn new() -> std::io::Result<Self> {
        let sandbox = Self::default();
        sandbox.version_launcher()?;
        Ok(sandbox)
    }

    pub fn with_roots(
        workspace: Option<&Path>,
        extra_roots: &SandboxExtraRoots,
    ) -> std::io::Result<Self> {
        let sandbox = Self {
            workspace: workspace.map(Path::to_path_buf),
            extra_roots: extra_roots.clone(),
        };
        sandbox.version_launcher()?;
        sandbox.validated_roots()?;
        Ok(sandbox)
    }

    fn probe_launch(
        &self,
        launcher: &Path,
        support: BubblewrapHardeningSupport,
        timeout: Duration,
    ) -> std::io::Result<()> {
        let mut cmd = Command::new("/usr/bin/true");
        self.wrap_command_with_launcher(&mut cmd, support, launcher)?;
        // An anonymous file avoids a full stderr pipe deadlocking the probe.
        // Only a bounded diagnostic is read back, including on setup failure.
        let mut diagnostic = tempfile::tempfile()?;
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(diagnostic.try_clone()?));
        let mut child = cmd.spawn().map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("Bubblewrap launch probe failed: {error}"),
            )
        })?;
        let deadline = Instant::now() + timeout;
        loop {
            match child.try_wait() {
                Ok(Some(status)) if status.success() => return Ok(()),
                Ok(Some(status)) => {
                    diagnostic.seek(SeekFrom::Start(0))?;
                    let mut bytes = Vec::new();
                    diagnostic.take(4096).read_to_end(&mut bytes)?;
                    return Err(std::io::Error::other(format!(
                        "Bubblewrap launch probe failed ({status}): {}",
                        String::from_utf8_lossy(&bytes).trim()
                    )));
                }
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                result => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(result.err().unwrap_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "Bubblewrap launch probe timed out; commands are blocked",
                        )
                    }));
                }
            }
        }
    }

    fn invalid(message: impl Into<String>) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, message.into())
    }

    fn validated_path(path: &Path) -> std::io::Result<PathBuf> {
        if !path.is_absolute()
            || path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(Self::invalid(format!(
                "Bubblewrap requires an absolute root without '..': {}",
                path.display()
            )));
        }
        let canonical = path.canonicalize().map_err(|e| {
            Self::invalid(format!(
                "Bubblewrap root {} is unavailable: {e}",
                path.display()
            ))
        })?;
        // Do not let replacement symlinks retarget a previously authorized root.
        if canonical != path {
            return Err(Self::invalid(format!(
                "Bubblewrap root must use its canonical path (no symlink roots): {}",
                path.display()
            )));
        }
        let home = std::env::var_os("HOME").map(PathBuf::from);
        if canonical == Path::new("/")
            || ["/tmp", "/home", "/usr", "/etc", "/dev", "/proc", "/sys"]
                .iter()
                .any(|p| canonical == Path::new(p))
            || home.as_ref().is_some_and(|h| h.starts_with(&canonical))
        {
            return Err(Self::invalid(format!(
                "Bubblewrap refuses broad host root: {}",
                path.display()
            )));
        }
        Ok(canonical)
    }

    fn validated_roots(&self) -> std::io::Result<(PathBuf, Vec<(PathBuf, bool)>)> {
        if !self.extra_roots.write_only.is_empty() {
            return Err(Self::invalid(
                "Bubblewrap cannot enforce write-only roots; commands are blocked",
            ));
        }
        let workspace =
            Self::validated_path(self.workspace.as_deref().ok_or_else(|| {
                Self::invalid("Bubblewrap requires the selected agent workspace")
            })?)?;
        if !workspace.is_dir() {
            return Err(Self::invalid("Bubblewrap workspace must be a directory"));
        }
        let mut roots = vec![(workspace.clone(), false)];
        for (paths, read_only) in [
            (&self.extra_roots.read_write, false),
            (&self.extra_roots.read_only, true),
        ] {
            for path in paths {
                let root = Self::validated_path(path)?;
                if roots.iter().any(|(p, ro)| *p == root && *ro != read_only) {
                    return Err(Self::invalid(format!(
                        "Bubblewrap conflicting root permissions: {}",
                        root.display()
                    )));
                }
                roots.push((root, read_only));
            }
        }
        // Most-specific grants must be mounted last, including read-only
        // subtrees of the writable workspace.
        roots.sort_by_key(|(p, _)| p.components().count());
        roots.dedup();
        Ok((workspace, roots))
    }

    fn rust_toolchain() -> std::io::Result<Option<(PathBuf, String)>> {
        let Ok(rustup) = resolve_executable(OsStr::new("rustup")) else {
            return Ok(None);
        };
        let output = Command::new(rustup).args(["which", "rustc"]).output()?;
        if !output.status.success() {
            return Err(Self::invalid(
                "Bubblewrap could not resolve the installed Rust toolchain",
            ));
        }
        let rustc = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
        let toolchain = rustc
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| Self::invalid("Bubblewrap invalid Rust toolchain path"))?
            .canonicalize()?;
        for child in ["bin/cargo", "bin/rustc", "lib"] {
            if !toolchain.join(child).exists() {
                return Err(Self::invalid("Bubblewrap incomplete Rust toolchain"));
            }
        }
        let version = Command::new(toolchain.join("bin/rustc"))
            .arg("-vV")
            .output()?;
        let version_text = String::from_utf8_lossy(&version.stdout);
        let host = version_text
            .lines()
            .find_map(|line| line.strip_prefix("host: "))
            .filter(|host| {
                !host.is_empty()
                    && host
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
            })
            .filter(|_| version.status.success())
            .ok_or_else(|| Self::invalid("Bubblewrap could not resolve the Rust host target"))?;
        Ok(Some((toolchain, host.to_owned())))
    }

    pub fn probe() -> std::io::Result<Self> {
        Self::new()
    }

    fn resolve_launcher() -> std::io::Result<PathBuf> {
        resolve_executable(OsStr::new("bwrap")).map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("Bubblewrap launcher could not be resolved: {error}"),
            )
        })
    }

    fn version_launcher(&self) -> std::io::Result<PathBuf> {
        let launcher = Self::resolve_launcher()?;
        let output = Command::new(&launcher)
            .arg("--version")
            .output()
            .map_err(|error| {
                std::io::Error::new(
                    error.kind(),
                    format!(
                        "Bubblewrap launcher at {} could not be probed: {error}",
                        launcher.display()
                    ),
                )
            })?;
        if !output.status.success() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!(
                    "Bubblewrap launcher at {} is unavailable",
                    launcher.display()
                ),
            ));
        }

        Ok(launcher)
    }

    fn detect_hardening_support(launcher: &std::path::Path) -> BubblewrapHardeningSupport {
        let support = Command::new(launcher)
            .arg("--help")
            .env_clear()
            .output()
            .map(|output| {
                Self::support_from_help(
                    &String::from_utf8_lossy(&output.stdout),
                    &String::from_utf8_lossy(&output.stderr),
                )
            })
            .unwrap_or_default();

        Self::log_incomplete_hardening_support(support);
        support
    }

    #[cfg(test)]
    fn for_test() -> Self {
        let workspace = std::env::current_dir().unwrap().canonicalize().unwrap();
        Self {
            workspace: Some(workspace),
            extra_roots: SandboxExtraRoots::default(),
        }
    }

    fn support_from_help(stdout: &str, stderr: &str) -> BubblewrapHardeningSupport {
        let contains = |flag| stdout.contains(flag) || stderr.contains(flag);

        BubblewrapHardeningSupport {
            cap_drop: contains("--cap-drop"),
        }
    }

    fn log_incomplete_hardening_support(support: BubblewrapHardeningSupport) {
        if support.cap_drop {
            return;
        }

        ::zeroclaw_log::record!(
            WARN,
            ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                .with_outcome(::zeroclaw_log::EventOutcome::Unknown)
                .with_attrs(::serde_json::json!({
                    "backend": "bubblewrap",
                    "cap_drop": support.cap_drop,
                })),
            "bubblewrap sandbox hardening support is incomplete"
        );
    }

    fn append_capability_drops(cmd: &mut Command, support: BubblewrapHardeningSupport) {
        if !support.cap_drop {
            return;
        }

        for capability in CAPABILITY_DROPS {
            cmd.args(["--cap-drop", capability]);
        }
    }

    #[cfg(test)]
    fn wrap_command_with_support(
        &self,
        cmd: &mut Command,
        support: BubblewrapHardeningSupport,
    ) -> std::io::Result<()> {
        self.wrap_command_with_launcher(cmd, support, Path::new("bwrap"))
    }

    fn wrap_command_with_launcher(
        &self,
        cmd: &mut Command,
        support: BubblewrapHardeningSupport,
        launcher: &Path,
    ) -> std::io::Result<()> {
        let invocation = super::shell_identity::invocation(cmd, None)?;
        self.wrap_invocation(cmd, support, launcher, &invocation)
    }

    fn wrap_invocation(
        &self,
        cmd: &mut Command,
        support: BubblewrapHardeningSupport,
        launcher: &Path,
        invocation: &[OsString],
    ) -> std::io::Result<()> {
        let (workspace, roots) = self.validated_roots()?;
        let cwd = cmd.get_current_dir().unwrap_or(&workspace);
        let cwd = Self::validated_path(cwd)?;
        if !cwd.is_dir() || !roots.iter().any(|(root, _)| cwd.starts_with(root)) {
            return Err(Self::invalid(
                "Bubblewrap working directory is outside authorized roots",
            ));
        }
        let mut bwrap_cmd = Command::new(launcher);
        bwrap_cmd.env_clear();
        for (key, value) in cmd.get_envs() {
            match value {
                Some(value) => {
                    bwrap_cmd.env(key, value);
                }
                None => {
                    bwrap_cmd.env_remove(key);
                }
            }
        }
        bwrap_cmd.current_dir(&cwd);
        bwrap_cmd.args([
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind",
            "/usr/local",
            "/usr/local",
            "--ro-bind",
            "/bin",
            "/bin",
            "--ro-bind",
            "/sbin",
            "/sbin",
            "--dev",
            "/dev",
            // No procfs: fresh mounts conflict with inherited systemd masks,
            // while binding inherited procfs leaks outer process command lines.
            // PID isolation is retained, and no host proc view is exposed.
            "--tmpfs",
            "/proc",
            "--remount-ro",
            "/proc",
            "--tmpfs",
            "/tmp",
            "--dir",
            "/tmp/home",
            "--dir",
            "/tmp/rustup",
            "--unshare-all",
            "--die-with-parent",
        ]);
        Self::append_capability_drops(&mut bwrap_cmd, support);
        for lib_dir in &["/lib64", "/lib"] {
            if std::path::Path::new(lib_dir).exists() {
                bwrap_cmd.args(["--ro-bind", lib_dir, lib_dir]);
            }
        }
        for (root, read_only) in roots {
            bwrap_cmd
                .arg(if read_only { "--ro-bind" } else { "--bind" })
                .arg(&root)
                .arg(&root);
        }
        let cargo_home = workspace.join(".zeroclaw-cargo");
        // Scoped writable Cargo locks/state and build products. Reject symlinks
        // before creating anything, including symlinks to another workspace.
        for path in [&cargo_home, &workspace.join(".zeroclaw-target")] {
            if std::fs::symlink_metadata(path).is_ok() {
                Self::validated_path(path)?;
            }
            bwrap_cmd.arg("--dir").arg(path);
        }
        let registry = cargo_home.join("registry");
        if registry.exists() {
            let registry = Self::validated_path(&registry)?;
            bwrap_cmd.arg("--ro-bind").arg(&registry).arg(&registry);
        }
        let mut path = OsString::from("/usr/local/bin:/usr/bin:/bin");
        if let Some((toolchain, host)) = Self::rust_toolchain()? {
            // Direct toolchain executables avoid mounting rustup shims or the
            // user's Cargo/Rustup settings, credentials, and arbitrary home.
            for child in ["bin", "lib"] {
                let source = toolchain.join(child);
                bwrap_cmd.arg("--ro-bind").arg(&source).arg(&source);
            }
            // Rust's ELF loader and bundled lld wrapper discover their own
            // paths through /proc/self/exe. Use the already-mounted library
            // directory and the installed native C linker instead. This is a
            // per-command Cargo setting, not a workspace/config mutation.
            bwrap_cmd
                .args(["--setenv", "LD_LIBRARY_PATH"])
                .arg(toolchain.join("lib"));
            let compiler = Path::new("/usr/bin/cc").canonicalize()?;
            if !compiler.starts_with("/usr") {
                return Err(Self::invalid(
                    "Bubblewrap system compiler must resolve inside /usr",
                ));
            }
            let linker_key = format!(
                "CARGO_TARGET_{}_LINKER",
                host.to_ascii_uppercase().replace('-', "_")
            );
            bwrap_cmd.arg("--setenv").arg(linker_key).arg(compiler);
            // Fedora's /usr/bin/ld points outside /usr through alternatives.
            // Expose only this executable, never the alternatives directory
            // or the rest of /etc, and never an out-of-/usr replacement.
            let alternative = Path::new("/etc/alternatives/ld");
            if alternative.exists() {
                let linker = alternative.canonicalize()?;
                if !linker.starts_with("/usr") {
                    return Err(Self::invalid(
                        "Bubblewrap system linker must resolve inside /usr",
                    ));
                }
                bwrap_cmd.arg("--ro-bind").arg(linker).arg(alternative);
            }
            path = toolchain.join("bin").into_os_string();
            path.push(":/usr/local/bin:/usr/bin:/bin");
        }
        for (key, value) in [
            ("PATH", path),
            ("HOME", OsString::from("/tmp/home")),
            ("RUSTUP_HOME", OsString::from("/tmp/rustup")),
            ("CARGO_HOME", cargo_home.into_os_string()),
            (
                "CARGO_TARGET_DIR",
                workspace.join(".zeroclaw-target").into_os_string(),
            ),
            ("TMPDIR", OsString::from("/tmp")),
        ] {
            bwrap_cmd.arg("--setenv").arg(key).arg(value);
        }
        bwrap_cmd.arg("--chdir").arg(cwd).arg("--");
        bwrap_cmd.args(invocation);

        *cmd = bwrap_cmd;
        Ok(())
    }
}

impl Sandbox for BubblewrapSandbox {
    fn wrap_shell_command(
        &self,
        cmd: &mut Command,
        shell_program: Option<&OsStr>,
    ) -> std::io::Result<()> {
        let invocation = super::shell_identity::invocation(cmd, shell_program)?;
        let launcher = Self::resolve_launcher()?;
        let support = Self::detect_hardening_support(&launcher);
        self.wrap_invocation(cmd, support, &launcher, &invocation)
    }

    fn wrap_command(&self, cmd: &mut Command) -> std::io::Result<()> {
        let launcher = Self::resolve_launcher()?;
        let support = Self::detect_hardening_support(&launcher);
        self.wrap_command_with_launcher(cmd, support, &launcher)
    }

    fn check_launch(&self) -> std::io::Result<()> {
        // Readiness is distinct from constructor validity: mount restrictions
        // or namespace restrictions may prohibit launches without invalidating in-process
        // tools or delegation. Status probes the actual workspace mount plan
        // on demand; construction must not cripple the whole agent turn.
        let launcher = Self::resolve_launcher()?;
        let support = Self::detect_hardening_support(&launcher);
        self.probe_launch(&launcher, support, Duration::from_secs(5))
    }

    fn is_available(&self) -> bool {
        self.version_launcher().is_ok()
    }

    fn name(&self) -> &str {
        "bubblewrap"
    }

    fn description(&self) -> &str {
        "User namespace sandbox (requires bwrap)"
    }

    fn coding_cli_unsupported_reason(&self) -> Option<&'static str> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bubblewrap_shell_identity_survives_replacing_wrapper() {
        let mut cmd = Command::new("/usr/bin/busybox");
        cmd.args(["-c", "printf '%s' \"$0\""]);
        let invocation =
            crate::security::shell_identity::invocation_with(&cmd, Some(OsStr::new("sh")), || {
                Ok(PathBuf::from("/usr/bin/env"))
            })
            .unwrap();
        BubblewrapSandbox::for_test()
            .wrap_invocation(
                &mut cmd,
                BubblewrapHardeningSupport::default(),
                Path::new("/usr/bin/bwrap"),
                &invocation,
            )
            .unwrap();
        assert_eq!(cmd.get_program(), "/usr/bin/bwrap");
        assert!(
            cmd.get_args().collect::<Vec<_>>().ends_with(
                &invocation
                    .iter()
                    .map(OsString::as_os_str)
                    .collect::<Vec<_>>()
            )
        );
    }

    fn args(cmd: &Command) -> Vec<String> {
        cmd.get_args()
            .map(|s| s.to_string_lossy().to_string())
            .collect()
    }

    #[test]
    fn bubblewrap_sandbox_name() {
        let sandbox = BubblewrapSandbox::for_test();
        assert_eq!(sandbox.name(), "bubblewrap");
    }

    #[test]
    fn bubblewrap_is_available_only_if_installed() {
        // Result depends on whether bwrap is installed
        let sandbox = BubblewrapSandbox::for_test();
        let _available = sandbox.is_available();

        // Either way, the name should still work
        assert_eq!(sandbox.name(), "bubblewrap");
    }

    #[cfg(unix)]
    #[test]
    fn bubblewrap_wrap_uses_the_resolved_launcher_identity() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let launcher = dir.path().join("bwrap");
        std::fs::write(&launcher, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o755)).unwrap();
        let launcher = launcher.canonicalize().unwrap();
        let sandbox = BubblewrapSandbox::for_test();
        assert!(
            Command::new(&launcher)
                .arg("--version")
                .output()
                .unwrap()
                .status
                .success()
        );
        let support = BubblewrapSandbox::detect_hardening_support(&launcher);
        let mut command = Command::new("echo");
        sandbox
            .wrap_command_with_launcher(&mut command, support, &launcher)
            .unwrap();
        assert_eq!(command.get_program(), launcher.as_os_str());
    }

    #[cfg(unix)]
    #[test]
    fn bubblewrap_launch_probe_rejects_launcher_that_versions_but_cannot_launch() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = tempfile::tempdir().unwrap();
        let launcher = fixture.path().join("bwrap");
        std::fs::write(&launcher, "#!/bin/sh\ncase \"$1\" in --version) exit 0;; --help) echo --cap-drop; exit 0;; esac\necho 'synthetic protected-proc failure' >&2\nexit 1\n").unwrap();
        std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            Command::new(&launcher)
                .arg("--version")
                .status()
                .unwrap()
                .success()
        );
        let sandbox = BubblewrapSandbox::for_test();
        sandbox.check_initialization().unwrap();
        let error = sandbox
            .probe_launch(
                &launcher,
                BubblewrapHardeningSupport { cap_drop: true },
                Duration::from_secs(1),
            )
            .unwrap_err();
        assert!(error.to_string().contains("Bubblewrap launch probe failed"));
        assert!(
            error
                .to_string()
                .contains("synthetic protected-proc failure")
        );
    }

    #[cfg(unix)]
    #[test]
    fn bubblewrap_launch_probe_reaps_timeout_and_reports_spawn_failure() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = tempfile::tempdir().unwrap();
        let launcher = fixture.path().join("bwrap");
        // exec avoids leaving a shell descendant behind when the probe kills it.
        std::fs::write(&launcher, "#!/bin/sh\nexec /usr/bin/sleep 30\n").unwrap();
        std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o755)).unwrap();
        let sandbox = BubblewrapSandbox::for_test();
        let start = Instant::now();
        let error = sandbox
            .probe_launch(
                &launcher,
                BubblewrapHardeningSupport::default(),
                Duration::from_millis(30),
            )
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(start.elapsed() < Duration::from_secs(2));
        let error = sandbox
            .probe_launch(
                &fixture.path().join("missing"),
                BubblewrapHardeningSupport::default(),
                Duration::from_secs(1),
            )
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        assert!(error.to_string().contains("launch probe failed"));
    }

    // ── §1.1 Sandbox isolation flag tests ──────────────────────

    #[test]
    fn bubblewrap_wrap_command_includes_isolation_flags() {
        let sandbox = BubblewrapSandbox::for_test();
        let mut cmd = Command::new("echo");
        cmd.arg("hello");
        sandbox
            .wrap_command_with_support(&mut cmd, BubblewrapHardeningSupport::default())
            .unwrap();

        assert_eq!(
            cmd.get_program().to_string_lossy(),
            "bwrap",
            "wrapped command should use bwrap as program"
        );

        let args = args(&cmd);

        assert!(
            args.contains(&"--unshare-all".to_string()),
            "must include --unshare-all for namespace isolation"
        );
        assert!(
            args.contains(&"--die-with-parent".to_string()),
            "must include --die-with-parent to prevent orphan processes"
        );
        assert!(
            !args.contains(&"--share-net".to_string()),
            "must NOT include --share-net (network should be blocked)"
        );
    }

    #[test]
    fn bubblewrap_supported_capability_drops_include_admin_and_ptrace() {
        let mut cmd = Command::new("bwrap");
        BubblewrapSandbox::append_capability_drops(
            &mut cmd,
            BubblewrapHardeningSupport { cap_drop: true },
        );

        let args = args(&cmd);
        let expected_capability_drops = ["CAP_SYS_ADMIN", "CAP_SYS_PTRACE"];
        for capability in expected_capability_drops {
            assert!(
                args.windows(2)
                    .any(|window| window == ["--cap-drop", capability]),
                "supported bubblewrap hardening must drop {capability}"
            );
        }
    }

    #[test]
    fn bubblewrap_skips_capability_drops_when_not_advertised() {
        let mut cmd = Command::new("bwrap");
        BubblewrapSandbox::append_capability_drops(
            &mut cmd,
            BubblewrapHardeningSupport { cap_drop: false },
        );

        assert!(
            args(&cmd).is_empty(),
            "unsupported bubblewrap capability drops should not be appended"
        );
    }

    #[test]
    fn bubblewrap_support_from_help_detects_stdout_and_stderr_flags() {
        assert!(BubblewrapSandbox::support_from_help("--cap-drop", "").cap_drop);
        assert!(BubblewrapSandbox::support_from_help("", "--cap-drop").cap_drop);
        assert!(!BubblewrapSandbox::support_from_help("", "").cap_drop);
    }

    #[test]
    fn bubblewrap_sandbox_preserves_coding_cli_semantics() {
        let sandbox = BubblewrapSandbox::for_test();
        assert!(sandbox.coding_cli_unsupported_reason().is_none());
    }

    #[test]
    fn bubblewrap_wrap_command_applies_supported_capability_drops() {
        let sandbox = BubblewrapSandbox::for_test();
        let mut cmd = Command::new("echo");
        sandbox
            .wrap_command_with_support(&mut cmd, BubblewrapHardeningSupport { cap_drop: true })
            .unwrap();

        let args = args(&cmd);
        let expected_capability_drops = ["CAP_SYS_ADMIN", "CAP_SYS_PTRACE"];
        for capability in expected_capability_drops {
            assert!(
                args.windows(2)
                    .any(|window| window == ["--cap-drop", capability]),
                "wrap_command must apply supported bubblewrap drop for {capability}"
            );
        }
    }

    #[test]
    fn bubblewrap_wrap_command_does_not_add_bare_seccomp_without_profile_fd() {
        let sandbox = BubblewrapSandbox::for_test();
        let mut cmd = Command::new("echo");
        sandbox
            .wrap_command_with_support(&mut cmd, BubblewrapHardeningSupport::default())
            .unwrap();

        assert!(
            !args(&cmd).contains(&"--seccomp".to_string()),
            "bubblewrap --seccomp requires a seccomp BPF profile fd and must not be added bare"
        );
    }

    #[test]
    fn bubblewrap_wrap_command_preserves_original_command() {
        let sandbox = BubblewrapSandbox::for_test();
        let mut cmd = Command::new("ls");
        cmd.arg("-la");
        cmd.arg("/tmp");
        sandbox
            .wrap_command_with_support(&mut cmd, BubblewrapHardeningSupport::default())
            .unwrap();

        let args = args(&cmd);

        assert!(
            args.contains(&"ls".to_string()),
            "original program must be passed as argument"
        );
        assert!(
            args.contains(&"-la".to_string()),
            "original args must be preserved"
        );
        assert!(
            args.contains(&"/tmp".to_string()),
            "original args must be preserved"
        );
    }

    #[test]
    fn bubblewrap_wrap_command_conditionally_binds_lib_dirs() {
        // /lib64 and /lib must be bind-mounted (with --ro-bind src dst) when
        // they exist on the host so that dynamically linked binaries (e.g.
        // `cargo`) can find the ELF interpreter and shared libraries inside the
        // sandbox.
        let sandbox = BubblewrapSandbox::for_test();
        let mut cmd = Command::new("echo");
        sandbox
            .wrap_command_with_support(&mut cmd, BubblewrapHardeningSupport::default())
            .unwrap();

        let args = args(&cmd);

        for lib_dir in &["/lib64", "/lib"] {
            if std::path::Path::new(lib_dir).exists() {
                // Verify the triplet `--ro-bind <dir> <dir>` is present and in
                // the correct order; a bare path without the flag would be silently
                // ignored by bwrap and leave the sandbox broken.
                let has_ro_bind_triplet = args
                    .windows(3)
                    .any(|w| w[0] == "--ro-bind" && w[1] == *lib_dir && w[2] == *lib_dir);
                assert!(
                    has_ro_bind_triplet,
                    "{lib_dir} exists on host but --ro-bind {lib_dir} {lib_dir} \
                     is missing from bwrap args — dynamically linked binaries \
                     will fail inside the sandbox"
                );
            }
        }
    }

    #[test]
    fn bubblewrap_wrap_command_binds_required_paths() {
        let sandbox = BubblewrapSandbox::for_test();
        let mut cmd = Command::new("echo");
        sandbox
            .wrap_command_with_support(&mut cmd, BubblewrapHardeningSupport::default())
            .unwrap();

        let args = args(&cmd);

        assert!(
            args.contains(&"--ro-bind".to_string()),
            "must include read-only bind for /usr"
        );
        assert!(args.contains(&"/usr".to_string()), "must include /usr bind");
        assert!(
            args.contains(&"/usr/local".to_string()),
            "must include /usr/local bind for tools like python3"
        );
        assert!(
            args.contains(&"/bin".to_string()),
            "must include /bin bind for core system tools"
        );
        assert!(
            args.contains(&"/sbin".to_string()),
            "must include /sbin bind for system administration tools"
        );
        assert!(
            args.contains(&"--dev".to_string()),
            "must include /dev mount"
        );
        assert!(
            args.windows(2).any(|w| w == ["--tmpfs", "/proc"])
                && args.windows(2).any(|w| w == ["--remount-ro", "/proc"]),
            "procfs must be omitted rather than exposing outer processes"
        );
        assert!(
            !args.windows(3).any(|w| {
                matches!(w[0].as_str(), "--bind" | "--ro-bind")
                    && w[1] == "/proc"
                    && w[2] == "/proc"
            }),
            "inherited procfs exposes outer process command lines"
        );
        assert!(!args.iter().any(|arg| arg == "--proc"));
        if let Some((toolchain, host)) = BubblewrapSandbox::rust_toolchain().unwrap() {
            assert!(args.windows(3).any(|w| w
                == [
                    "--setenv",
                    "LD_LIBRARY_PATH",
                    toolchain.join("lib").to_str().unwrap()
                ]));
            let key = format!(
                "CARGO_TARGET_{}_LINKER",
                host.to_ascii_uppercase().replace('-', "_")
            );
            assert!(args.windows(3).any(|w| w[0] == "--setenv"
                && w[1] == key
                && Path::new(&w[2]).starts_with("/usr")));
        }
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;

    fn sandbox(workspace: &Path, extra_roots: SandboxExtraRoots) -> BubblewrapSandbox {
        BubblewrapSandbox {
            workspace: Some(workspace.to_path_buf()),
            extra_roots,
        }
    }

    fn wrapped(sandbox: &BubblewrapSandbox, cwd: &Path) -> Command {
        let mut cmd = Command::new("/usr/bin/printf");
        cmd.arg("identity")
            .current_dir(cwd)
            .env("SAFE_SENTINEL", "retained");
        sandbox
            .wrap_command_with_support(&mut cmd, BubblewrapHardeningSupport { cap_drop: true })
            .unwrap();
        cmd
    }

    #[test]
    fn bubblewrap_mounts_only_selected_workspace_and_policy_roots() {
        let fixture = tempfile::tempdir().unwrap();
        let ws = fixture.path().join("kat");
        let cwd = ws.join("project");
        let ro = fixture.path().join("reference");
        let rw = fixture.path().join("authorized");
        let other = fixture.path().join("dirk");
        for p in [&cwd, &ro, &rw, &other] {
            std::fs::create_dir_all(p).unwrap();
        }
        let sandbox = sandbox(
            &ws,
            SandboxExtraRoots {
                read_write: vec![rw.clone()],
                read_only: vec![ro.clone()],
                write_only: vec![],
            },
        );
        let cmd = wrapped(&sandbox, &cwd);
        let args = cmd.get_args().map(OsStr::to_owned).collect::<Vec<_>>();
        let bind = |flag: &str, path: &Path| {
            args.windows(3)
                .any(|w| w == [OsStr::new(flag), path.as_os_str(), path.as_os_str()])
        };
        assert!(bind("--bind", &ws));
        assert!(bind("--bind", &rw));
        assert!(bind("--ro-bind", &ro));
        assert!(!bind("--bind", Path::new("/tmp")));
        assert!(
            args.windows(2)
                .any(|w| w == [OsStr::new("--tmpfs"), OsStr::new("/tmp")])
        );
        assert!(
            args.windows(2)
                .any(|w| w == [OsStr::new("--chdir"), cwd.as_os_str()])
        );
        for denied in [
            &other,
            &PathBuf::from(std::env::var_os("HOME").unwrap()),
            &PathBuf::from("/etc"),
            &PathBuf::from("/home/jeremy/.config"),
        ] {
            assert!(!bind("--bind", denied));
            assert!(!bind("--ro-bind", denied));
        }
        assert_eq!(cmd.get_current_dir(), Some(cwd.as_path()));
        assert_eq!(
            cmd.get_envs()
                .find(|(k, _)| *k == "SAFE_SENTINEL")
                .unwrap()
                .1,
            Some(OsStr::new("retained"))
        );
        assert!(args.ends_with(&[
            OsString::from("--"),
            OsString::from("/usr/bin/printf"),
            OsString::from("identity")
        ]));
        for (key, value) in [
            ("HOME", PathBuf::from("/tmp/home")),
            ("RUSTUP_HOME", PathBuf::from("/tmp/rustup")),
            ("CARGO_HOME", ws.join(".zeroclaw-cargo")),
            ("CARGO_TARGET_DIR", ws.join(".zeroclaw-target")),
            ("TMPDIR", PathBuf::from("/tmp")),
        ] {
            assert!(
                args.windows(3)
                    .any(|w| w == [OsStr::new("--setenv"), OsStr::new(key), value.as_os_str()])
            );
        }
    }

    #[test]
    fn bubblewrap_invalid_roots_and_cwd_fail_without_replacing_command() {
        let ws = tempfile::tempdir().unwrap();
        for roots in [
            SandboxExtraRoots {
                write_only: vec![ws.path().into()],
                ..Default::default()
            },
            SandboxExtraRoots {
                read_only: vec![ws.path().join("missing")],
                ..Default::default()
            },
            SandboxExtraRoots {
                read_write: vec![PathBuf::from("relative")],
                ..Default::default()
            },
            SandboxExtraRoots {
                read_write: vec![PathBuf::from("/tmp")],
                ..Default::default()
            },
        ] {
            let sandbox = sandbox(ws.path(), roots);
            let mut cmd = Command::new("/bin/echo");
            assert!(
                sandbox
                    .wrap_command_with_support(&mut cmd, BubblewrapHardeningSupport::default())
                    .is_err()
            );
            assert_eq!(cmd.get_program(), "/bin/echo");
        }
        let sandbox = sandbox(ws.path(), SandboxExtraRoots::default());
        let mut cmd = Command::new("/bin/echo");
        cmd.current_dir("/usr/bin");
        assert!(
            sandbox
                .wrap_command_with_support(&mut cmd, BubblewrapHardeningSupport::default())
                .is_err()
        );
        let sandbox = BubblewrapSandbox::default();
        assert!(sandbox.validated_roots().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn bubblewrap_rejects_retargeted_roots_and_scoped_cargo_symlinks() {
        let fixture = tempfile::tempdir().unwrap();
        let ws = fixture.path().join("kat");
        let other = fixture.path().join("dirk");
        std::fs::create_dir(&ws).unwrap();
        std::fs::create_dir(&other).unwrap();
        std::os::unix::fs::symlink(&other, ws.join(".zeroclaw-cargo")).unwrap();
        let sandbox = sandbox(&ws, SandboxExtraRoots::default());
        let mut cmd = Command::new("/bin/echo");
        assert!(
            sandbox
                .wrap_command_with_support(&mut cmd, BubblewrapHardeningSupport::default())
                .is_err()
        );
        std::os::unix::fs::symlink(&other, fixture.path().join("root")).unwrap();
        assert!(BubblewrapSandbox::validated_path(&fixture.path().join("root")).is_err());
    }
}
