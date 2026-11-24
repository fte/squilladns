use squilladns::bind::{
    claim_zone_owner, dynamic_zone_config, release_zone_owner, set_zone_owner_state, OwnerError,
    OwnerState, RndcClient, RndcError,
};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;

fn temp_dir(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("squilladns-{}-{}", label, std::process::id()));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn first_tenant_owns_a_global_dns_name_until_release() {
    let dir = temp_dir("bind-owner");
    let first = claim_zone_owner(&dir, "example.test", "tenant-a").unwrap();
    assert!(first.created);
    assert_eq!(first.state, OwnerState::Inactive);

    set_zone_owner_state(&dir, "example.test", "tenant-a", OwnerState::Active).unwrap();
    let retry = claim_zone_owner(&dir, "example.test", "tenant-a").unwrap();
    assert!(!retry.created);
    assert_eq!(retry.state, OwnerState::Active);
    assert_eq!(
        claim_zone_owner(&dir, "example.test", "tenant-b"),
        Err(OwnerError::Conflict)
    );

    release_zone_owner(&dir, "example.test", "tenant-a").unwrap();
    let second = claim_zone_owner(&dir, "example.test", "tenant-b").unwrap();
    assert!(second.created);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn dynamic_zone_config_quotes_file_paths_and_rejects_control_chars() {
    assert_eq!(
        dynamic_zone_config(r#"/srv/zones/example\"quoted.db"#).unwrap(),
        r#"{ type primary; file "/srv/zones/example\\\"quoted.db"; };"#
    );
    assert!(dynamic_zone_config("/srv/zones/zone\nfile").is_err());
}

#[test]
fn rndc_client_passes_config_and_arguments_without_a_shell() {
    let dir = temp_dir("fake-rndc");
    let executable = dir.join("rndc-check-args");
    fs::write(
        &executable,
        "#!/bin/sh\n[ \"$1\" = \"-c\" ] || exit 41\n[ \"$2\" = \"/mock/rndc.conf\" ] || exit 42\n[ \"$3\" = \"reload\" ] || exit 43\n[ \"$4\" = \"example.test\" ] || exit 44\n",
    )
    .unwrap();
    let mut permissions = fs::metadata(&executable).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&executable, permissions).unwrap();

    let client = RndcClient::new(
        executable,
        Some(PathBuf::from("/mock/rndc.conf")),
        Duration::from_secs(1),
    )
    .unwrap();
    client.reload_zone("example.test").unwrap();
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn rndc_client_enforces_timeout_and_returns_command_failure() {
    let shell = RndcClient::new(PathBuf::from("/bin/sh"), None, Duration::from_millis(30)).unwrap();
    assert_eq!(shell.run(&["-c", "exec sleep 2"]), Err(RndcError::TimedOut));

    let shell = RndcClient::new(PathBuf::from("/bin/sh"), None, Duration::from_secs(1)).unwrap();
    assert_eq!(
        shell.run(&["-c", "exit 7"]),
        Err(RndcError::CommandFailed(Some(7)))
    );
}
