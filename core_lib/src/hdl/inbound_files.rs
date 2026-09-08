use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use anyhow::{anyhow, Result};
use rand::Rng;

const STAGING_DIR_PREFIX: &str = ".rquickshare-staging-";

/// Validate a file name supplied by a remote peer before it is joined to the
/// local download directory.
///
/// A remote name must describe exactly one ordinary path component.  In
/// particular, both slash variants are rejected explicitly so that the
/// validation has the same result on Unix and Windows.
pub(crate) fn validate_remote_filename(name: &str) -> Result<()> {
    if name.is_empty() || name.contains('/') || name.contains('\\') || name.contains('\0') {
        return Err(anyhow!("invalid remote file name"));
    }

    let mut components = Path::new(name).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(component)), None) if component.to_str() == Some(name) => Ok(()),
        _ => Err(anyhow!("remote file name must be a single path component")),
    }
}

/// Select a destination without reusing an existing path or a destination
/// already selected for another file in this introduction frame.
pub(crate) fn choose_destination(
    download_dir: &Path,
    name: &str,
    reserved: &mut HashSet<PathBuf>,
) -> Result<PathBuf> {
    validate_remote_filename(name)?;

    let mut candidate = download_dir.join(name);
    let mut counter = 1u64;
    loop {
        if !candidate.exists() && reserved.insert(candidate.clone()) {
            return Ok(candidate);
        }

        let suffix = format!("{}_{}", counter, name);
        candidate = download_dir.join(suffix);
        counter = counter
            .checked_add(1)
            .ok_or_else(|| anyhow!("too many files with the same name"))?;
    }
}

/// Create a private temporary file in a random staging directory below the
/// destination directory. If the destination filesystem cannot represent the
/// requested private permissions, retry below the OS temporary directory. A
/// temporary root may be on another filesystem; finalization then uses the
/// exclusive-copy fallback instead of a hard link.
pub(crate) fn create_temp_file(download_dir: &Path, payload_id: i64) -> Result<(PathBuf, File)> {
    create_temp_file_with_roots(
        download_dir,
        &std::env::temp_dir(),
        payload_id,
        is_private_staging_path,
    )
}

fn create_temp_file_with_roots<F>(
    download_dir: &Path,
    fallback_root: &Path,
    payload_id: i64,
    is_private: F,
) -> Result<(PathBuf, File)>
where
    F: Fn(&Path) -> bool + Copy,
{
    fs::create_dir_all(download_dir)?;

    if let Some(file) = try_create_temp_file(download_dir, payload_id, is_private)? {
        return Ok(file);
    }

    try_create_temp_file(fallback_root, payload_id, is_private)?.ok_or_else(|| {
        anyhow!("unable to create a private receive file in the download or OS temporary directory")
    })
}

fn try_create_temp_file<F>(
    staging_root: &Path,
    _payload_id: i64,
    is_private: F,
) -> Result<Option<(PathBuf, File)>>
where
    F: Fn(&Path) -> bool,
{
    let staging_dir = create_staging_dir(staging_root)?;
    let path = staging_dir.join(format!(
        "payload-{:032x}.part",
        rand::rng().random::<u128>()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);

    let file = match options.open(&path) {
        Ok(file) => file,
        Err(error) => {
            let _ = fs::remove_dir(&staging_dir);
            return Err(error.into());
        }
    };

    if is_private(&path) {
        return Ok(Some((path, file)));
    }

    drop(file);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_dir(&staging_dir);
    Ok(None)
}

fn create_staging_dir(download_dir: &Path) -> Result<PathBuf> {
    for _ in 0..32 {
        let name = format!("{STAGING_DIR_PREFIX}{:032x}", rand::rng().random::<u128>());
        let path = download_dir.join(name);
        let mut builder = fs::DirBuilder::new();
        builder.recursive(false);
        #[cfg(unix)]
        builder.mode(0o700);

        match builder.create(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }

    Err(anyhow!("unable to allocate a private receive directory"))
}

/// Remove a temporary payload and its now-empty private staging directory.
/// Missing paths are treated as already cleaned up so this helper is safe to
/// call from cancellation and drop cleanup paths.
pub(crate) fn cleanup_temp_file(temp_path: &Path) -> io::Result<()> {
    let mut first_error = None;

    let staging_dir = staging_dir_for(temp_path);
    let staging_metadata = staging_dir.and_then(|path| fs::symlink_metadata(path).ok());
    let can_remove_payload = staging_metadata
        .as_ref()
        .is_some_and(|metadata| metadata.file_type().is_dir())
        && {
            #[cfg(unix)]
            {
                staging_metadata
                    .as_ref()
                    .is_some_and(|metadata| metadata.permissions().mode() & 0o777 == 0o700)
            }
            #[cfg(not(unix))]
            {
                true
            }
        };

    if can_remove_payload {
        match fs::symlink_metadata(temp_path) {
            Ok(metadata) if metadata.file_type().is_file() => match fs::remove_file(temp_path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => first_error = Some(error),
            },
            Ok(_) | Err(_) => {}
        }
    }

    if let Some(staging_dir) = staging_dir {
        if staging_metadata
            .as_ref()
            .is_some_and(|metadata| metadata.file_type().is_symlink())
        {
            match fs::remove_file(staging_dir) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) if first_error.is_none() => first_error = Some(error),
                Err(_) => {}
            }
            return first_error.map_or(Ok(()), Err);
        }

        match fs::remove_dir(staging_dir) {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::DirectoryNotEmpty
                ) => {}
            Err(error) if first_error.is_none() => first_error = Some(error),
            Err(_) => {}
        }
    }

    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn staging_dir_for(temp_path: &Path) -> Option<&Path> {
    let staging_dir = temp_path.parent()?;
    let name = staging_dir.file_name()?.to_str()?;
    name.starts_with(STAGING_DIR_PREFIX).then_some(staging_dir)
}

fn is_private_staging_path(temp_path: &Path) -> bool {
    let Some(staging_dir) = staging_dir_for(temp_path) else {
        return false;
    };
    let Ok(staging_metadata) = fs::symlink_metadata(staging_dir) else {
        return false;
    };
    if !staging_metadata.file_type().is_dir() {
        return false;
    }
    #[cfg(unix)]
    if staging_metadata.permissions().mode() & 0o777 != 0o700 {
        return false;
    }

    let Ok(file_metadata) = fs::symlink_metadata(temp_path) else {
        return false;
    };
    if !file_metadata.file_type().is_file() {
        return false;
    }
    #[cfg(unix)]
    if file_metadata.permissions().mode() & 0o777 != 0o600 {
        return false;
    }

    true
}

fn validate_staging_path(temp_path: &Path, desired_path: &Path) -> Result<()> {
    let staging_dir = staging_dir_for(temp_path)
        .ok_or_else(|| anyhow!("temporary receive file is outside a private staging directory"))?;
    let destination_dir = desired_path
        .parent()
        .ok_or_else(|| anyhow!("destination has no parent directory"))?;
    let temporary_root = std::env::temp_dir();
    if staging_dir.parent() != Some(destination_dir)
        && staging_dir.parent() != Some(temporary_root.as_path())
    {
        return Err(anyhow!(
            "temporary receive file is outside an approved staging root"
        ));
    }

    let staging_metadata = fs::symlink_metadata(staging_dir)?;
    if !staging_metadata.file_type().is_dir() {
        return Err(anyhow!("temporary receive staging path is not a directory"));
    }
    #[cfg(unix)]
    if staging_metadata.permissions().mode() & 0o777 != 0o700 {
        return Err(anyhow!(
            "temporary receive staging directory is not private"
        ));
    }

    let file_metadata = fs::symlink_metadata(temp_path)?;
    if !file_metadata.file_type().is_file() {
        return Err(anyhow!("temporary receive path is not a regular file"));
    }
    #[cfg(unix)]
    if file_metadata.permissions().mode() & 0o777 != 0o600 {
        return Err(anyhow!("temporary receive file is not private"));
    }

    Ok(())
}

/// Publish a completed temporary file without replacing an existing file.
/// Hard-linking is an atomic no-replace operation on the same filesystem.  If
/// the staging and destination filesystems do not support hard links or are
/// different filesystems, an exclusive copy is used after the transfer has
/// completed. If the requested destination appeared after metadata was
/// received, a numbered destination is selected.
pub(crate) fn finalize_temp_file(temp_path: &Path, desired_path: &Path) -> Result<PathBuf> {
    validate_staging_path(temp_path, desired_path)?;

    let parent = desired_path
        .parent()
        .ok_or_else(|| anyhow!("destination has no parent directory"))?;
    let name = desired_path
        .file_name()
        .ok_or_else(|| anyhow!("destination has no file name"))?
        .to_string_lossy();

    for counter in 0u64.. {
        let candidate = if counter == 0 {
            desired_path.to_path_buf()
        } else {
            parent.join(format!("{}_{}", counter, name))
        };

        match fs::hard_link(temp_path, &candidate) {
            Ok(()) => {
                if let Err(error) = cleanup_temp_file(temp_path) {
                    // Avoid leaving two names for the received content when
                    // cleanup of the temporary name fails.
                    let _ = fs::remove_file(&candidate);
                    return Err(error.into());
                }
                return Ok(candidate);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) if should_copy_after_hard_link_error(&error) => {
                match copy_temp_file_exclusive(temp_path, &candidate) {
                    Ok(()) => {
                        cleanup_temp_file(temp_path)?;
                        return Ok(candidate);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => return Err(error.into()),
                }
            }
            Err(error) => return Err(error.into()),
        }
    }

    Err(anyhow!("unable to allocate a final receive path"))
}

fn should_copy_after_hard_link_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Unsupported | io::ErrorKind::CrossesDevices
    )
}

/// Copy a complete temporary file to a destination opened with `create_new`.
/// This fallback is necessarily less atomic than `hard_link`, but it still
/// never replaces an existing destination and removes a partial destination on
/// copy or sync failure.
fn copy_temp_file_exclusive(temp_path: &Path, destination: &Path) -> io::Result<()> {
    let mut source = File::open(temp_path)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);

    let mut output = options.open(destination)?;

    let result = (|| {
        io::copy(&mut source, &mut output)?;
        output.sync_all()
    })();
    drop(output);

    if let Err(error) = result {
        let _ = fs::remove_file(destination);
        return Err(error);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn test_directory() -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("rquickshare-inbound-{suffix}"));
        fs::create_dir(&path).expect("create test directory");
        path
    }

    #[test]
    fn rejects_names_that_escape_download_directory() {
        for name in [
            "",
            ".",
            "..",
            "../outside",
            "nested/file",
            r"nested\file",
            "/absolute",
        ] {
            assert!(validate_remote_filename(name).is_err(), "accepted {name:?}");
        }

        assert!(validate_remote_filename(".profile").is_ok());
        assert!(validate_remote_filename("photo.jpg").is_ok());
    }

    #[test]
    fn reserves_duplicate_names_within_one_introduction() {
        let directory = test_directory();
        let mut reserved = HashSet::new();

        let first = choose_destination(&directory, "photo.jpg", &mut reserved).unwrap();
        let second = choose_destination(&directory, "photo.jpg", &mut reserved).unwrap();

        assert_eq!(first, directory.join("photo.jpg"));
        assert_eq!(second, directory.join("1_photo.jpg"));
        assert_ne!(first, second);

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn finalization_does_not_replace_existing_file() {
        let directory = test_directory();
        let desired = directory.join("photo.jpg");
        fs::write(&desired, b"old").unwrap();

        let (temporary, mut file) = create_temp_file(&directory, 7).unwrap();
        std::io::Write::write_all(&mut file, b"new").unwrap();
        drop(file);

        let finalized = finalize_temp_file(&temporary, &desired).unwrap();
        assert_eq!(fs::read(&desired).unwrap(), b"old");
        assert_eq!(fs::read(&finalized).unwrap(), b"new");
        assert!(!temporary.exists());
        assert!(!temporary.parent().unwrap().exists());

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn temporary_file_is_private_and_can_be_removed_after_abort() {
        let directory = test_directory();
        let (temporary, file) = create_temp_file(&directory, 19).unwrap();

        #[cfg(unix)]
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);

        drop(file);
        cleanup_temp_file(&temporary).unwrap();
        assert!(!temporary.exists());
        assert!(!temporary.parent().unwrap().exists());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn staging_directory_is_private_and_remote_part_names_remain_destinations() {
        let directory = test_directory();
        let (temporary, file) = create_temp_file(&directory, 19).unwrap();
        let staging_directory = temporary.parent().unwrap();

        assert_eq!(staging_directory.parent(), Some(directory.as_path()));
        assert_ne!(temporary, directory.join(".rquickshare-19-0.part"));
        let mut reserved = HashSet::new();
        let destination =
            choose_destination(&directory, ".rquickshare-19-0.part", &mut reserved).unwrap();
        assert_eq!(destination, directory.join(".rquickshare-19-0.part"));

        #[cfg(unix)]
        {
            assert_eq!(
                fs::symlink_metadata(staging_directory)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        }

        drop(file);
        cleanup_temp_file(&temporary).unwrap();
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn falls_back_to_os_temp_when_destination_staging_is_not_private() {
        let directory = test_directory();
        let fallback_root = std::env::temp_dir();
        let (temporary, mut file) =
            create_temp_file_with_roots(&directory, &fallback_root, 29, |path| {
                path.parent().and_then(Path::parent) != Some(directory.as_path())
                    && is_private_staging_path(path)
            })
            .unwrap();

        assert_eq!(
            temporary.parent().unwrap().parent(),
            Some(fallback_root.as_path())
        );
        std::io::Write::write_all(&mut file, b"from-temp").unwrap();
        drop(file);

        let desired = directory.join("from-temp.bin");
        let finalized = finalize_temp_file(&temporary, &desired).unwrap();
        assert_eq!(fs::read(finalized).unwrap(), b"from-temp");
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn hard_link_cross_device_errors_select_the_exclusive_copy_fallback() {
        assert!(should_copy_after_hard_link_error(&io::Error::from(
            io::ErrorKind::Unsupported,
        )));
        assert!(should_copy_after_hard_link_error(&io::Error::from(
            io::ErrorKind::CrossesDevices,
        )));
        assert!(!should_copy_after_hard_link_error(&io::Error::from(
            io::ErrorKind::PermissionDenied,
        )));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_replaced_staging_directory_symlink() {
        use std::os::unix::fs::symlink;

        let directory = test_directory();
        let desired = directory.join("photo.jpg");
        let (temporary, mut file) = create_temp_file(&directory, 23).unwrap();
        std::io::Write::write_all(&mut file, b"new").unwrap();
        drop(file);

        let staging_directory = temporary.parent().unwrap().to_owned();
        let attacker_directory = directory.join("attacker");
        fs::create_dir(&attacker_directory).unwrap();
        fs::write(attacker_directory.join("payload.part"), b"attacker").unwrap();
        fs::remove_file(&temporary).unwrap();
        fs::remove_dir(&staging_directory).unwrap();
        symlink(&attacker_directory, &staging_directory).unwrap();

        assert!(finalize_temp_file(&temporary, &desired).is_err());
        assert!(!desired.exists());
        assert_eq!(
            fs::read(attacker_directory.join("payload.part")).unwrap(),
            b"attacker"
        );

        cleanup_temp_file(&temporary).unwrap();
        assert_eq!(
            fs::read(attacker_directory.join("payload.part")).unwrap(),
            b"attacker"
        );
        fs::remove_dir_all(directory).unwrap();
    }
}
