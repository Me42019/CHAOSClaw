//! Private tool-result storage. Session and call identity come from the turn
//! engine; the only caller-supplied lookup key is a fixed-width opaque ID.

use sha2::{Digest, Sha256};
use std::path::PathBuf;
use tokio::sync::Semaphore;

pub(crate) const MAX_ARTIFACT_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const MAX_SLICE_BYTES: usize = 512;
pub(crate) const MAX_RESPONSE_BYTES: usize = 4096;
#[cfg(unix)]
const DIRECTORY: &str = "tool-output-v1";
static WORKERS: Semaphore = Semaphore::const_new(4);

#[derive(Clone)]
pub(crate) struct ToolOutputStore {
    install_root: PathBuf,
    scope: String,
    // Steering and provider switches can reenter the same turn at round 0.
    invocation: uuid::Uuid,
}

fn digest(parts: &[&[u8]]) -> String {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    format!("{:x}", hash.finalize())
}

fn valid_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}

impl ToolOutputStore {
    pub(super) fn new(
        install_root: PathBuf,
        agent: &str,
        surface: &str,
        session: &str,
        principal: &str,
    ) -> Option<Self> {
        if !cfg!(unix) || !install_root.is_absolute() || agent.is_empty() || session.is_empty() {
            return None;
        }
        Some(Self {
            install_root,
            scope: digest(&[
                agent.as_bytes(),
                surface.as_bytes(),
                session.as_bytes(),
                principal.as_bytes(),
            ]),
            invocation: uuid::Uuid::new_v4(),
        })
    }

    pub(super) async fn archive(
        &self,
        turn: &str,
        iteration: usize,
        slot: usize,
        call_id: Option<&str>,
        output: std::sync::Arc<String>,
    ) -> Option<String> {
        if turn.is_empty() || output.is_empty() || output.len() > MAX_ARTIFACT_BYTES {
            return None;
        }
        let permit = tokio::time::timeout(std::time::Duration::from_millis(250), WORKERS.acquire())
            .await
            .ok()?
            .ok()?;
        let id = self.artifact_id(turn, iteration, slot, call_id);
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            store.write(&id, output.as_bytes()).ok()?;
            Some(id)
        })
        .await
        .ok()
        .flatten()
    }

    pub(crate) async fn read(&self, id: &str, offset: u64, length: usize) -> Option<OutputSlice> {
        if !valid_id(id) || length == 0 || length > MAX_SLICE_BYTES {
            return None;
        }
        let permit = tokio::time::timeout(std::time::Duration::from_millis(250), WORKERS.acquire())
            .await
            .ok()?
            .ok()?;
        let store = self.clone();
        let id = id.to_owned();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            store.read_slice(&id, offset, length).ok()
        })
        .await
        .ok()
        .flatten()
    }

    fn artifact_id(
        &self,
        turn: &str,
        iteration: usize,
        slot: usize,
        call_id: Option<&str>,
    ) -> String {
        digest(&[
            self.scope.as_bytes(),
            self.invocation.as_bytes(),
            turn.as_bytes(),
            &(iteration as u64).to_be_bytes(),
            &(slot as u64).to_be_bytes(),
            call_id.unwrap_or_default().as_bytes(),
        ])
    }

    fn filename(&self, id: &str) -> String {
        digest(&[self.scope.as_bytes(), id.as_bytes()])
    }
}

pub(crate) struct OutputSlice {
    pub(crate) total_bytes: u64,
    pub(crate) data: Vec<u8>,
}

#[cfg(unix)]
mod disk {
    use super::*;
    use cap_std::ambient_authority;
    use cap_std::fs::{Dir, DirBuilder, DirBuilderExt, MetadataExt, OpenOptions, OpenOptionsExt};
    use std::io::{self, Read, Seek, SeekFrom, Write};
    use std::path::Component;

    const MAX_STORE_BYTES: u64 = 64 * 1024 * 1024;
    const MAX_ARTIFACTS: usize = 512;
    const LOCK: &str = "writer-lock";
    const PENDING: &str = "pending-write";

    fn invalid() -> io::Error {
        io::Error::from(io::ErrorKind::InvalidData)
    }

    fn open_directory(parent: &Dir, name: impl AsRef<std::path::Path>) -> io::Result<Dir> {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_NONBLOCK);
        parent
            .open_with(name, &options)
            .map(|file| Dir::from_std_file(file.into_std()))
    }

    fn sync_directory(dir: &Dir) -> io::Result<()> {
        dir.try_clone()?.into_std_file().sync_all()
    }

    fn private_file(
        dir: &Dir,
        name: &str,
        write: bool,
        exclusive: bool,
    ) -> io::Result<std::fs::File> {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(write)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        if exclusive {
            options.create_new(true);
        } else {
            options.create(write);
        }
        let file = dir.open_with(name, &options)?;
        let metadata = file.metadata()?;
        // SAFETY: geteuid reads the current process's effective UID.
        if !metadata.is_file()
            || metadata.mode() & 0o777 != 0o600
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err(invalid());
        }
        if metadata.nlink() != 1 {
            // Read-only opens target published names. The one permitted
            // extra link is the writer's staging name, which may survive a
            // crash after publication. Check the inode without following
            // symlinks. A writer may also have just removed the staging name.
            let valid_links = !write
                && metadata.nlink() == 2
                && (dir.symlink_metadata(PENDING).is_ok_and(|pending| {
                    pending.is_file()
                        && pending.dev() == metadata.dev()
                        && pending.ino() == metadata.ino()
                }) || file.metadata()?.nlink() == 1);
            if !valid_links {
                return Err(invalid());
            }
        }
        Ok(file.into_std())
    }

    fn remove_pending(dir: &Dir) -> io::Result<()> {
        match dir.remove_file(PENDING) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    impl ToolOutputStore {
        fn directory(&self, create: bool) -> io::Result<Dir> {
            let mut parent = Dir::open_ambient_dir("/", ambient_authority())?;
            for component in self.install_root.components() {
                match component {
                    Component::RootDir => {}
                    Component::Normal(name) => parent = open_directory(&parent, name)?,
                    _ => return Err(invalid()),
                }
            }
            if create {
                let mut builder = DirBuilder::new();
                builder.mode(0o700);
                match parent.create_dir_with(DIRECTORY, &builder) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error),
                }
                // A retry must also be durable after a previous parent fsync failure.
                sync_directory(&parent)?;
            }
            let dir = open_directory(&parent, DIRECTORY)?;
            let metadata = dir.dir_metadata()?;
            // SAFETY: geteuid reads the current process's effective UID.
            if metadata.mode() & 0o777 != 0o700 || metadata.uid() != unsafe { libc::geteuid() } {
                return Err(invalid());
            }
            Ok(dir)
        }

        pub(super) fn write(&self, id: &str, bytes: &[u8]) -> io::Result<()> {
            let dir = self.directory(true)?;
            let lock = private_file(&dir, LOCK, true, false)?;
            // Nonblocking across processes. A busy writer goes through the
            // ordinary truncation fallback instead of queueing another write.
            lock.try_lock().map_err(io::Error::from)?;
            remove_pending(&dir)?;
            let name = self.filename(id);
            match private_file(&dir, &name, false, false) {
                Ok(existing) => {
                    let mut present = Vec::new();
                    existing
                        .take(bytes.len() as u64 + 1)
                        .read_to_end(&mut present)?;
                    if present != bytes {
                        return Err(invalid());
                    }
                    return sync_directory(&dir);
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }

            // Bounded scan under the cross-process writer lock. A foreign or
            // malformed entry fails closed, including unexpected subdirectories.
            let mut used = bytes.len() as u64;
            let mut artifacts = 0;
            for (index, entry) in dir.entries()?.enumerate() {
                if index > MAX_ARTIFACTS {
                    return Err(invalid());
                }
                let entry = entry?;
                let name = entry.file_name();
                if name == LOCK {
                    continue;
                }
                let metadata = entry.metadata()?;
                if !name.to_str().is_some_and(valid_id)
                    || !metadata.is_file()
                    || metadata.len() > MAX_ARTIFACT_BYTES as u64
                {
                    return Err(invalid());
                }
                used += metadata.len();
                artifacts += 1;
                if used > MAX_STORE_BYTES || artifacts >= MAX_ARTIFACTS {
                    return Err(invalid());
                }
            }

            let result = (|| {
                let mut pending = private_file(&dir, PENDING, true, true)?;
                pending.write_all(bytes)?;
                pending.sync_all()?;
                // Same-directory link publishes the full synced inode without
                // overwriting a destination. The staging name is never readable
                // via an artifact ID, and a crashed writer leaves at most one.
                dir.hard_link(PENDING, &dir, &name)?;
                Ok(())
            })();
            let cleanup = remove_pending(&dir);
            result.and(cleanup)?;
            sync_directory(&dir)
        }

        pub(super) fn read_slice(
            &self,
            id: &str,
            offset: u64,
            length: usize,
        ) -> io::Result<OutputSlice> {
            let dir = self.directory(false)?;
            let mut file = private_file(&dir, &self.filename(id), false, false)?;
            let total_bytes = file.metadata()?.len();
            if total_bytes > MAX_ARTIFACT_BYTES as u64 || offset > total_bytes {
                return Err(invalid());
            }
            let mut data = vec![0; length.min((total_bytes - offset) as usize)];
            file.seek(SeekFrom::Start(offset))?;
            file.read_exact(&mut data)?;
            Ok(OutputSlice { total_bytes, data })
        }
    }
}

#[cfg(not(unix))]
impl ToolOutputStore {
    fn write(&self, _id: &str, _bytes: &[u8]) -> std::io::Result<()> {
        Err(std::io::ErrorKind::Unsupported.into())
    }

    fn read_slice(&self, _id: &str, _offset: u64, _length: usize) -> std::io::Result<OutputSlice> {
        Err(std::io::ErrorKind::Unsupported.into())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::tools::tool_output_read::{TOOL_OUTPUT_READ_SCOPE, ToolOutputRead};
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
    use std::path::Path;
    use std::sync::Arc;
    use zeroclaw_api::tool::Tool;

    fn store(root: &Path, agent: &str, session: &str) -> ToolOutputStore {
        ToolOutputStore::new(root.canonicalize().unwrap(), agent, "rpc", session, "owner").unwrap()
    }

    async fn archive(store: &ToolOutputStore, original: &str) -> Option<String> {
        store
            .archive("turn", 0, 0, Some("call"), Arc::new(original.into()))
            .await
    }

    fn original() -> String {
        format!("{}MID🚀{}", "a".repeat(3800), "z".repeat(1900))
    }

    #[test]
    fn restart_recovers_exact_bytes_in_another_process() {
        const CHILD_ROOT: &str = "CHAOSCLAW_GATE1_TEST_REOPEN_ROOT";
        const CHILD_ID: &str = "CHAOSCLAW_GATE1_TEST_REOPEN_ID";
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let original = original();
        if let Some(root) = std::env::var_os(CHILD_ROOT) {
            runtime.block_on(async {
                let id = std::env::var(CHILD_ID).unwrap();
                let reopened = store(Path::new(&root), "kat", "session-a");
                let mut recovered = Vec::new();
                for offset in (0..original.len()).step_by(MAX_SLICE_BYTES) {
                    let page = reopened
                        .read(&id, offset as u64, MAX_SLICE_BYTES)
                        .await
                        .unwrap();
                    recovered.extend(page.data);
                }
                assert_eq!(recovered, original.as_bytes());
                assert_eq!(
                    reopened.read(&id, 3801, 6).await.unwrap().data,
                    &original.as_bytes()[3801..3807]
                );
            });
            return;
        }

        for interrupted_cleanup in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let owner = store(temp.path(), "kat", "session-a");
            let path = temp.path().join(DIRECTORY);
            let pending = path.join("pending-write");
            let id = if interrupted_cleanup {
                // Reproduce the exact disk state after syncing and linking
                // the staged inode, before unlinking or syncing the directory.
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&path)
                    .unwrap();
                let mut file = std::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .mode(0o600)
                    .open(&pending)
                    .unwrap();
                file.write_all(original.as_bytes()).unwrap();
                file.sync_all().unwrap();
                let id = owner.artifact_id("turn", 0, 0, Some("call"));
                std::fs::hard_link(&pending, path.join(owner.filename(&id))).unwrap();
                assert_eq!(file.metadata().unwrap().nlink(), 2);
                id
            } else {
                runtime.block_on(archive(&owner, &original)).unwrap()
            };

            let child = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "agent::turn::tool_output_store::tests::restart_recovers_exact_bytes_in_another_process"])
                .env(CHILD_ROOT, temp.path())
                .env(CHILD_ID, id)
                .output()
                .unwrap();
            assert!(
                child.status.success(),
                "interrupted cleanup: {interrupted_cleanup}\n{}",
                String::from_utf8_lossy(&child.stdout)
            );
            assert!(String::from_utf8_lossy(&child.stdout).contains("1 passed"));
            assert_eq!(pending.exists(), interrupted_cleanup);
        }
    }

    #[tokio::test]
    async fn read_rejects_unrelated_extra_links_and_staging_symlink() {
        let temp = tempfile::tempdir().unwrap();
        let owner = store(temp.path(), "kat", "session-a");
        let id = archive(&owner, "complete").await.unwrap();
        let dir = temp.path().join(DIRECTORY);
        let stored = dir.join(owner.filename(&id));
        let unrelated_link = temp.path().join("unrelated-link");
        let pending = dir.join("pending-write");
        std::fs::hard_link(&stored, &unrelated_link).unwrap();
        assert!(owner.read(&id, 0, 20).await.is_none());

        std::fs::write(&pending, b"unrelated staging").unwrap();
        assert!(owner.read(&id, 0, 20).await.is_none());
        std::fs::remove_file(&pending).unwrap();
        symlink(&stored, &pending).unwrap();
        assert!(owner.read(&id, 0, 20).await.is_none());
        std::fs::remove_file(&pending).unwrap();

        std::fs::hard_link(&stored, &pending).unwrap();
        assert_eq!(std::fs::metadata(&stored).unwrap().nlink(), 3);
        assert!(owner.read(&id, 0, 20).await.is_none());
    }

    #[tokio::test]
    async fn retrieval_validates_scope_range_and_serialized_size() {
        let temp = tempfile::tempdir().unwrap();
        let owner = store(temp.path(), "kat", "session-a");
        let input = format!("autoridad🚀{}", "<".repeat(MAX_SLICE_BYTES));
        let id = archive(&owner, &input).await.unwrap();
        for foreign in [
            store(temp.path(), "norman", "session-a"),
            store(temp.path(), "kat", "session-b"),
            ToolOutputStore::new(
                temp.path().to_owned(),
                "kat",
                "rpc",
                "session-a",
                "other-owner",
            )
            .unwrap(),
            ToolOutputStore::new(
                temp.path().to_owned(),
                "kat",
                "channel",
                "session-a",
                "owner",
            )
            .unwrap(),
        ] {
            assert!(foreign.read(&id, 0, 1).await.is_none());
        }

        let call = |offset, length| {
            ToolOutputRead.execute(serde_json::json!({
                "artifact_id": id, "offset": offset, "length": length
            }))
        };
        assert!(!call(0, 1).await.unwrap().success);
        TOOL_OUTPUT_READ_SCOPE
            .scope(Some(owner.clone()), async {
                for (offset, length) in [(0, 0), (0, MAX_SLICE_BYTES + 1), (u64::MAX, 1)] {
                    assert!(!call(offset, length).await.unwrap().success);
                }
                let page = call(13, MAX_SLICE_BYTES).await.unwrap();
                assert!(page.success && page.output.len() < MAX_RESPONSE_BYTES);
                assert!(!page.output.contains('<'));
                let data = page.output.split_once('\n').unwrap().1;
                assert_eq!(
                    serde_json::from_str::<String>(data).unwrap(),
                    "<".repeat(MAX_SLICE_BYTES)
                );

                let page = call(10, 2).await.unwrap();
                let (header, data) = page.output.split_once('\n').unwrap();
                assert!(header.contains("base64"));
                use base64::{Engine, engine::general_purpose::STANDARD};
                let bytes = STANDARD
                    .decode(serde_json::from_str::<String>(data).unwrap())
                    .unwrap();
                assert_eq!(bytes, input.as_bytes()[10..12]);
            })
            .await;
        assert!(owner.read("../pending-write", 0, 1).await.is_none());
    }

    #[tokio::test]
    async fn duplicate_conflict_interruption_and_permissions() {
        let temp = tempfile::tempdir().unwrap();
        let owner = store(temp.path(), "kat", "session-a");
        let id = archive(&owner, "complete").await.unwrap();
        let dir = temp.path().join(DIRECTORY);
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let stored = dir.join(owner.filename(&id));
        assert_eq!(
            std::fs::metadata(&stored).unwrap().permissions().mode() & 0o777,
            0o600
        );

        assert_eq!(
            archive(&owner, "complete").await.as_deref(),
            Some(id.as_str())
        );
        assert!(archive(&owner, "conflict").await.is_none());
        assert_eq!(owner.read(&id, 0, 20).await.unwrap().data, b"complete");

        // State after a writer died before the atomic link.
        let pending = dir.join("pending-write");
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&pending)
            .unwrap();
        file.write_all(b"interrupted").unwrap();
        drop(file);
        let interrupted = owner.artifact_id("turn", 1, 0, Some("call"));
        assert!(owner.read(&interrupted, 0, 20).await.is_none());
        let written = owner
            .archive("turn", 1, 0, Some("call"), Arc::new("next output".into()))
            .await;
        assert_eq!(written.as_deref(), Some(interrupted.as_str()));
        assert!(!pending.exists());
        assert_eq!(
            owner.read(&interrupted, 0, 20).await.unwrap().data,
            b"next output"
        );

        // Replacing a committed file with a symlink cannot redirect a read
        // or make a retry publish an ID for the symlink target.
        std::fs::remove_file(&stored).unwrap();
        symlink(dir.join(owner.filename(&interrupted)), &stored).unwrap();
        assert!(owner.read(&id, 0, 20).await.is_none());
        assert!(archive(&owner, "complete").await.is_none());

        let foreign = tempfile::tempdir().unwrap();
        symlink(&dir, foreign.path().join(DIRECTORY)).unwrap();
        let foreign = store(foreign.path(), "kat", "session-a");
        assert!(foreign.read(&interrupted, 0, 20).await.is_none());
        assert!(archive(&foreign, "complete").await.is_none());
    }

    #[tokio::test]
    async fn quota_rejects_whole_new_artifacts() {
        let temp = tempfile::tempdir().unwrap();
        let store = store(temp.path(), "kat", "session-a");
        assert!(
            archive(&store, &"x".repeat(MAX_ARTIFACT_BYTES + 1))
                .await
                .is_none()
        );
        let existing_id = archive(&store, "first").await.unwrap();
        let dir = temp.path().join(DIRECTORY);
        for index in 0..16 {
            let path = dir.join(digest(&[b"quota-fixture", &[index]]));
            let file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(path)
                .unwrap();
            file.set_len(MAX_ARTIFACT_BYTES as u64 - 1).unwrap();
        }
        assert!(
            store
                .archive("turn", 0, 1, None, Arc::new("too much data".repeat(20)))
                .await
                .is_none()
        );
        assert_eq!(std::fs::read_dir(dir).unwrap().count(), 18);
        assert_eq!(
            store.read(&existing_id, 0, 20).await.unwrap().data,
            b"first"
        );
    }
}
