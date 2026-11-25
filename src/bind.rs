use std::fs::{self, OpenOptions};
use std::io;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

pub const DEFAULT_RNDC_TIMEOUT_SECS: u64 = 5;
static OWNER_TEMP_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug)]
pub struct RndcClient {
    executable: PathBuf,
    config_file: Option<PathBuf>,
    timeout: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RndcError {
    Unavailable,
    TimedOut,
    SpawnFailed,
    CommandFailed(Option<i32>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnerState {
    Inactive,
    Activating,
    Active,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnerClaim {
    pub created: bool,
    pub state: OwnerState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZoneOwner {
    pub tenant: String,
    pub state: OwnerState,
}

#[derive(Debug, PartialEq, Eq)]
pub enum OwnerError {
    Conflict,
    Io,
}

impl RndcClient {
    pub fn new(
        executable: PathBuf,
        config_file: Option<PathBuf>,
        timeout: Duration,
    ) -> Result<Self, String> {
        if timeout.is_zero() || timeout > Duration::from_secs(60) {
            return Err("rndc timeout must be between 1 and 60 seconds".into());
        }
        Ok(Self {
            executable,
            config_file,
            timeout,
        })
    }

    pub fn from_env() -> Result<Self, String> {
        let executable = std::env::var_os("RNDC_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("rndc"));
        let config_file = std::env::var_os("RNDC_CONF")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from);
        let timeout_secs = match std::env::var("RNDC_TIMEOUT_SECS") {
            Ok(value) => value
                .parse::<u64>()
                .ok()
                .filter(|seconds| (1..=60).contains(seconds))
                .ok_or_else(|| "RNDC_TIMEOUT_SECS must be between 1 and 60".to_string())?,
            Err(std::env::VarError::NotPresent) => DEFAULT_RNDC_TIMEOUT_SECS,
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err("RNDC_TIMEOUT_SECS must be valid UTF-8".into())
            }
        };

        Self::new(executable, config_file, Duration::from_secs(timeout_secs))
    }

    pub fn run(&self, args: &[&str]) -> Result<(), RndcError> {
        let mut command = Command::new(&self.executable);
        if let Some(config_file) = &self.config_file {
            command.arg("-c").arg(config_file);
        }
        command.args(args);
        let status = run_command_with_timeout(&mut command, self.timeout)?;
        if status.success() {
            Ok(())
        } else {
            Err(RndcError::CommandFailed(status.code()))
        }
    }

    pub fn reload_zone(&self, zone_name: &str) -> Result<(), RndcError> {
        self.run(&["reload", zone_name])
    }

    pub fn activate_zone(
        &self,
        zone_name: &str,
        zone_file: &str,
        previously_active: bool,
    ) -> Result<(), RndcError> {
        if previously_active {
            match self.reload_zone(zone_name) {
                Ok(()) => return Ok(()),
                Err(RndcError::CommandFailed(_)) => {}
                Err(error) => return Err(error),
            }
        }
        self.add_zone(zone_name, zone_file)
    }

    pub fn add_zone(&self, zone_name: &str, zone_file: &str) -> Result<(), RndcError> {
        let config = dynamic_zone_config(zone_file).map_err(|_| RndcError::SpawnFailed)?;
        self.run(&["addzone", zone_name, &config])
    }

    pub fn delete_zone(&self, zone_name: &str) -> Result<(), RndcError> {
        self.run(&["delzone", zone_name])
    }
}

/// Réserve le nom DNS au premier tenant qui le réclame. Le marqueur persistant
/// empêche un autre tenant d'activer son propre fichier sous le même nom.
pub fn claim_zone_owner(
    owners_dir: &std::path::Path,
    zone_name: &str,
    tenant: &str,
) -> Result<OwnerClaim, OwnerError> {
    fs::create_dir_all(owners_dir).map_err(|_| OwnerError::Io)?;
    let owner_path = owner_path(owners_dir, zone_name);
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&owner_path)
    {
        Ok(mut file) => {
            let data = format!("{}\tinactive\n", tenant);
            if file.write_all(data.as_bytes()).is_err() || file.sync_all().is_err() {
                let _ = fs::remove_file(&owner_path);
                return Err(OwnerError::Io);
            }
            Ok(OwnerClaim {
                created: true,
                state: OwnerState::Inactive,
            })
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let owner = read_zone_owner(owners_dir, zone_name)?.ok_or(OwnerError::Io)?;
            if owner.tenant != tenant {
                return Err(OwnerError::Conflict);
            }
            Ok(OwnerClaim {
                created: false,
                state: owner.state,
            })
        }
        Err(_) => Err(OwnerError::Io),
    }
}

pub fn read_zone_owner(
    owners_dir: &std::path::Path,
    zone_name: &str,
) -> Result<Option<ZoneOwner>, OwnerError> {
    let owner_path = owner_path(owners_dir, zone_name);
    let content = match fs::read_to_string(owner_path) {
        Ok(content) => content,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(OwnerError::Io),
    };
    let mut fields = content.trim().split('\t');
    let tenant = fields.next().ok_or(OwnerError::Io)?;
    let state = match fields.next() {
        Some("active") => OwnerState::Active,
        Some("activating") => OwnerState::Activating,
        Some("inactive") => OwnerState::Inactive,
        _ => return Err(OwnerError::Io),
    };
    Ok(Some(ZoneOwner {
        tenant: tenant.to_string(),
        state,
    }))
}

pub fn set_zone_owner_state(
    owners_dir: &std::path::Path,
    zone_name: &str,
    tenant: &str,
    state: OwnerState,
) -> Result<(), OwnerError> {
    let owner_path = owner_path(owners_dir, zone_name);
    let current = fs::read_to_string(&owner_path).map_err(|_| OwnerError::Io)?;
    let (current_tenant, _) = current.trim().split_once('\t').ok_or(OwnerError::Io)?;
    if current_tenant != tenant {
        return Err(OwnerError::Conflict);
    }

    let state = match state {
        OwnerState::Active => "active",
        OwnerState::Activating => "activating",
        OwnerState::Inactive => "inactive",
    };
    let temp_path = owners_dir.join(format!(
        ".{}.{}.{}.tmp",
        zone_name,
        std::process::id(),
        OWNER_TEMP_ID.fetch_add(1, Ordering::Relaxed)
    ));
    let write_result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .map_err(|_| OwnerError::Io)?;
        writeln!(file, "{}\t{}", tenant, state).map_err(|_| OwnerError::Io)?;
        file.sync_all().map_err(|_| OwnerError::Io)?;
        fs::rename(&temp_path, &owner_path).map_err(|_| OwnerError::Io)
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(temp_path);
    }
    write_result
}

pub fn release_zone_owner(
    owners_dir: &std::path::Path,
    zone_name: &str,
    tenant: &str,
) -> Result<(), OwnerError> {
    let owner_path = owner_path(owners_dir, zone_name);
    let current = match fs::read_to_string(&owner_path) {
        Ok(current) => current,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(OwnerError::Io),
    };
    if current.trim().split('\t').next() != Some(tenant) {
        return Err(OwnerError::Conflict);
    }
    fs::remove_file(owner_path).map_err(|_| OwnerError::Io)
}

fn owner_path(owners_dir: &std::path::Path, zone_name: &str) -> PathBuf {
    owners_dir.join(format!("{}.owner", zone_name))
}

pub fn dynamic_zone_config(zone_file: &str) -> Result<String, &'static str> {
    if zone_file.chars().any(char::is_control) {
        return Err("control characters are not allowed in zone file paths");
    }
    let mut escaped = String::with_capacity(zone_file.len());
    for character in zone_file.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            _ => escaped.push(character),
        }
    }
    Ok(format!("{{ type primary; file \"{}\"; }};", escaped))
}

fn run_command_with_timeout(
    command: &mut Command,
    timeout: Duration,
) -> Result<ExitStatus, RndcError> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                RndcError::Unavailable
            } else {
                RndcError::SpawnFailed
            }
        })?;
    wait_with_timeout(&mut child, timeout)
}

fn wait_with_timeout(child: &mut Child, timeout: Duration) -> Result<ExitStatus, RndcError> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(RndcError::TimedOut);
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(RndcError::SpawnFailed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rndc_runner_reports_success_and_failure_without_output_capture() {
        let mut success = Command::new("/bin/sh");
        success.args(["-c", "exit 0"]);
        assert!(
            run_command_with_timeout(&mut success, Duration::from_secs(1))
                .unwrap()
                .success()
        );

        let mut failure = Command::new("/bin/sh");
        failure.args(["-c", "exit 7"]);
        assert_eq!(
            run_command_with_timeout(&mut failure, Duration::from_secs(1))
                .unwrap()
                .code(),
            Some(7)
        );
    }

    #[test]
    fn rndc_runner_kills_a_timed_out_command() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "exec sleep 2"]);
        assert_eq!(
            run_command_with_timeout(&mut command, Duration::from_millis(30)),
            Err(RndcError::TimedOut)
        );
    }
}
