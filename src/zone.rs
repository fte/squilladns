use std::path::{Path, PathBuf};

use crate::Record;

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
    zone_dir
        .join(zone_name)
        .join(format!("{}.zone", zone_name))
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
    records: &[Record],
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
        .any(|record| record.record_type.eq_ignore_ascii_case("NS") && record.name == "@")
    {
        lines.push(format!("@ 3600 IN NS ns.{}.", zone_name));

        // BIND refuse une zone dont le NS de l'apex n'a aucune adresse :
        // on injecte un A par défaut si l'utilisateur n'en fournit pas.
        if !records.iter().any(|record| {
            record.name.eq_ignore_ascii_case("ns")
                && (record.record_type.eq_ignore_ascii_case("A")
                    || record.record_type.eq_ignore_ascii_case("AAAA"))
        }) {
            lines.push("ns 3600 IN A 127.0.0.1".into());
        }
    }

    // A records
    for r in records {
        if r.record_type == "A" {
            lines.push(format!("{} 3600 IN A {}", r.name, r.value));
        }
    }

    // AAAA records
    for r in records {
        if r.record_type == "AAAA" {
            lines.push(format!("{} 3600 IN AAAA {}", r.name, r.value));
        }
    }

    // CNAME records
    for r in records {
        if r.record_type == "CNAME" {
            lines.push(format!("{} 3600 IN CNAME {}", r.name, r.value));
        }
    }

    // MX records
    for r in records {
        if r.record_type == "MX" {
            let priority = r.value.split_whitespace().next().unwrap_or("10");
            let target = r.value.split_whitespace().nth(1).unwrap_or("");
            lines.push(format!("{} 3600 IN MX {} {}", r.name, priority, target));
        }
    }

    // NS records
    for r in records {
        if r.record_type == "NS" {
            lines.push(format!("{} 3600 IN NS {}", r.name, r.value));
        }
    }

    // TXT records
    for r in records {
        if r.record_type == "TXT" {
            lines.push(format!("{} 3600 IN TXT {}", r.name, r.value));
        }
    }

    // SRV records : value = "priority weight port target"
    for r in records {
        if r.record_type == "SRV" {
            let parts: Vec<&str> = r.value.split_whitespace().collect();
            if parts.len() >= 4 {
                lines.push(format!(
                    "{} 3600 IN SRV {} {} {} {}",
                    r.name, parts[0], parts[1], parts[2], parts[3]
                ));
            }
        }
    }

    // CAA records
    for r in records {
        if r.record_type == "CAA" {
            lines.push(format!("{} 3600 IN CAA {}", r.name, r.value));
        }
    }

    let zone_file_path = zone_path.join(format!("{}.zone", zone_name));
    std::fs::write(&zone_file_path, lines.join("\n") + "\n")
        .map_err(|e| format!("failed to write zone file: {}", e))?;

    Ok(zone_file_path)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let records = vec![Record {
            record_type: "A".into(),
            name: "www".into(),
            value: "192.0.2.1".into(),
        }];

        let path = generate_zone_file("alpha.test", &records, 2026010101, &dir).unwrap();
        assert_eq!(read_serial(&path), Some(2026010101));

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("ns.alpha.test."), "SOA doit utiliser la zone");
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
            Record {
                record_type: "NS".into(),
                name: "ns".into(),
                value: "ns.alpha.test.".into(),
            },
            Record {
                record_type: "A".into(),
                name: "ns".into(),
                value: "192.0.2.53".into(),
            },
        ];

        let path = generate_zone_file("alpha.test", &records, 1, &dir).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();

        assert!(content.contains("ns 3600 IN A 192.0.2.53"));
        assert!(!content.contains("127.0.0.1"));

        let _ = std::fs::remove_dir_all(dir);
    }
}
