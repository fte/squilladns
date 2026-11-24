use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::validation::{quote_master_file_string, ValidatedRData, ValidatedRecord};

static TEMP_FILE_ID: AtomicU64 = AtomicU64::new(0);

/// Chemin racine des zones pour example.invalid
pub fn zones_dir() -> PathBuf {
    PathBuf::from(
        std::env::var("ZONES_DIR").unwrap_or_else(|_| "zones/example.invalid".to_string()),
    )
}

/// Calcule le serial BIND9 pour une zone.
/// Règle : max(jours UTC depuis epoch, serial + 1)
pub fn compute_serial(existing_serial: Option<i32>) -> i32 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| (d.as_secs() / 86400) as i32)
        .unwrap_or(0);

    let next = existing_serial.map(|s| s + 1).unwrap_or(0);

    now.max(next)
}

/// Chemin du fichier de zone pour un répertoire de scope donné.
pub fn zone_file_path(zone_dir: &Path, zone_name: &str) -> PathBuf {
    zone_dir.join(zone_name).join(format!("{}.zone", zone_name))
}

/// Lit le serial actuel d'un fichier de zone (champ 3 de la ligne SOA).
pub fn read_serial(zone_file: &Path) -> Option<i32> {
    let content = std::fs::read_to_string(zone_file).ok()?;

    for line in content.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if let Some(idx) = tokens
            .iter()
            .position(|token| token.eq_ignore_ascii_case("SOA"))
        {
            // SOA <mname> <rname> <serial> <refresh> ...
            return tokens.get(idx + 3).and_then(|s| s.parse().ok());
        }
    }

    None
}

/// Génère le contenu d'un fichier de zone BIND9.
pub fn generate_zone_file(
    zone_name: &str,
    records: &[ValidatedRecord],
    serial: i32,
    zone_dir: &Path,
) -> Result<PathBuf, String> {
    let zone_path = zone_dir.join(zone_name);
    std::fs::create_dir_all(&zone_path).map_err(|e| format!("failed to create zone dir: {}", e))?;

    let mut lines: Vec<String> = Vec::new();

    // SOA record
    lines.push(format!(
        "@\t3600\tIN\tSOA\tns.{zone}. hostmaster.{zone}. {} 3600 900 604800 86400",
        serial,
        zone = zone_name
    ));

    if !records
        .iter()
        .any(|record| matches!(&record.data, ValidatedRData::Ns(_)) && record.name.is_none())
    {
        lines.push(format!("@ 3600 IN NS ns.{}.", zone_name));

        // BIND refuse une zone dont le NS de l'apex n'a aucune adresse :
        // on injecte un A par défaut si l'utilisateur n'en fournit pas.
        if !records.iter().any(|record| {
            record
                .name
                .as_ref()
                .is_some_and(|name| name.to_ascii().eq_ignore_ascii_case("ns"))
                && matches!(&record.data, ValidatedRData::A(_) | ValidatedRData::Aaaa(_))
        }) {
            lines.push("ns 3600 IN A 127.0.0.1".into());
        }
    }

    for r in records {
        let owner = r
            .name
            .as_ref()
            .map(|name| name.to_ascii())
            .unwrap_or_else(|| "@".into());
        let rdata = match &r.data {
            ValidatedRData::A(address) => format!("A {}", address),
            ValidatedRData::Aaaa(address) => format!("AAAA {}", address),
            ValidatedRData::Cname(target) => format!("CNAME {}", target.to_ascii()),
            ValidatedRData::Mx { priority, target } => {
                format!("MX {} {}", priority, target.to_ascii())
            }
            ValidatedRData::Ns(target) => format!("NS {}", target.to_ascii()),
            ValidatedRData::Txt(value) => {
                format!("TXT {}", quote_master_file_string(value))
            }
            ValidatedRData::Srv {
                priority,
                weight,
                port,
                target,
            } => format!("SRV {} {} {} {}", priority, weight, port, target.to_ascii()),
            ValidatedRData::Caa { flags, tag, value } => {
                format!("CAA {} {} {}", flags, tag, quote_master_file_string(value))
            }
        };
        lines.push(format!("{} 3600 IN {}", owner, rdata));
    }

    let zone_file_path = zone_path.join(format!("{}.zone", zone_name));
    let contents = lines.join("\n") + "\n";
    let temp_path = zone_path.join(format!(
        ".{}.{}.{}.tmp",
        zone_name,
        std::process::id(),
        TEMP_FILE_ID.fetch_add(1, Ordering::Relaxed)
    ));
    let write_result = (|| {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .map_err(|e| format!("failed to create temporary zone file: {}", e))?;
        file.write_all(contents.as_bytes())
            .map_err(|e| format!("failed to write temporary zone file: {}", e))?;
        file.sync_all()
            .map_err(|e| format!("failed to sync temporary zone file: {}", e))?;
        std::fs::rename(&temp_path, &zone_file_path)
            .map_err(|e| format!("failed to publish zone file: {}", e))
    })();
    if write_result.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }
    write_result?;

    Ok(zone_file_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validated_record(record_type: &str, name: &str, value: &str) -> ValidatedRecord {
        crate::validation::validate_record(&crate::Record {
            record_type: record_type.into(),
            name: name.into(),
            value: value.into(),
        })
        .unwrap()
    }

    #[test]
    fn zone_file_path_is_scope_ready() {
        let path = zone_file_path(Path::new("/zones/public"), "alpha.test");
        assert_eq!(
            path,
            PathBuf::from("/zones/public/alpha.test/alpha.test.zone")
        );
    }

    #[test]
    fn read_serial_roundtrip() {
        let dir = std::env::temp_dir().join(format!("squilladns-zone-{}", std::process::id()));
        let records = vec![validated_record("A", "www", "192.0.2.1")];

        let path = generate_zone_file("alpha.test", &records, 2026010101, &dir).unwrap();
        assert_eq!(read_serial(&path), Some(2026010101));

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            content.contains("ns.alpha.test."),
            "SOA doit utiliser la zone"
        );
        assert!(content.contains("IN NS ns.alpha.test."));
        assert!(
            content.contains("ns 3600 IN A 127.0.0.1"),
            "un A par défaut est requis pour que BIND charge la zone"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn no_default_a_when_user_provides_ns_address() {
        let dir = std::env::temp_dir().join(format!("squilladns-ns-{}", std::process::id()));
        let records = vec![
            validated_record("NS", "ns", "ns.alpha.test."),
            validated_record("A", "ns", "192.0.2.53"),
        ];

        let path = generate_zone_file("alpha.test", &records, 1, &dir).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();

        assert!(content.contains("ns 3600 IN A 192.0.2.53"));
        assert!(!content.contains("127.0.0.1"));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn txt_newline_is_escaped_and_cannot_inject_another_record() {
        let dir =
            std::env::temp_dir().join(format!("squilladns-txt-injection-{}", std::process::id()));
        let record = validated_record("TXT", "@", "\"ok\"\nevil 3600 IN A 203.0.113.66");
        let path = generate_zone_file("alpha.test", &[record], 1, &dir).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();

        let escaped = quote_master_file_string(b"\"ok\"\nevil 3600 IN A 203.0.113.66");
        assert_eq!(escaped, r#""\"ok\"\010evil 3600 IN A 203.0.113.66""#);
        assert!(content.contains(&format!("@ 3600 IN TXT {}", escaped)));
        assert!(!content.lines().any(|line| line.starts_with("evil ")));
        assert_eq!(content.lines().count(), 4);
        if std::process::Command::new("named-checkzone")
            .arg("-v")
            .output()
            .is_ok()
        {
            crate::validation::validate_zone_file_with_named_checkzone("alpha.test", &path)
                .unwrap();
        }

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn caa_value_is_quoted_and_escaped_in_master_file() {
        let dir =
            std::env::temp_dir().join(format!("squilladns-caa-escape-{}", std::process::id()));
        let record = validated_record("CAA", "@", r#"0 issue "example.com;\"bad""#);
        let path = generate_zone_file("alpha.test", &[record], 1, &dir).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();

        assert!(content.contains(r#"@ 3600 IN CAA 0 issue "example.com;\"bad""#));
        assert!(!content.lines().any(|line| line.starts_with("bad\"")));
        if std::process::Command::new("named-checkzone")
            .arg("-v")
            .output()
            .is_ok()
        {
            crate::validation::validate_zone_file_with_named_checkzone("alpha.test", &path)
                .unwrap();
        }

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn owner_name_with_zonefile_delimiter_is_rejected() {
        let record = crate::Record {
            record_type: "A".into(),
            name: "www;evil".into(),
            value: "192.0.2.20".into(),
        };
        assert!(crate::validation::validate_record(&record).is_err());
    }

    #[test]
    fn generation_replaces_the_full_record_set() {
        let dir = std::env::temp_dir().join(format!("squilladns-replace-{}", std::process::id()));
        let first = vec![validated_record("A", "old", "192.0.2.30")];
        let second = vec![validated_record("A", "new", "192.0.2.31")];

        let path = generate_zone_file("alpha.test", &first, 1, &dir).unwrap();
        generate_zone_file("alpha.test", &second, 2, &dir).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();

        assert!(content.contains("new 3600 IN A 192.0.2.31"));
        assert!(!content.contains("old 3600 IN A 192.0.2.30"));

        let _ = std::fs::remove_dir_all(dir);
    }
}
