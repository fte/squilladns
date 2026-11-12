use std::path::{Path, PathBuf};

use crate::Record;

/// Chemin racine des zones pour 575.be
pub fn zones_dir() -> PathBuf {
    PathBuf::from(
        std::env::var("ZONES_DIR")
            .unwrap_or_else(|_| "zones/575.be".to_string()),
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

/// Génère le contenu d'un fichier de zone BIND9.
pub fn generate_zone_file(
    zone_name: &str,
    records: &[Record],
    serial: i32,
    zone_dir: &Path,
) -> Result<PathBuf, String> {
    let zone_path = zone_dir.join(zone_name);
    std::fs::create_dir_all(&zone_path)
        .map_err(|e| format!("failed to create zone dir: {}", e))?;

    let mut lines: Vec<String> = Vec::new();

    // SOA record
    lines.push(format!(
        "@\t3600\tIN\tSOA\tns.575.be. hostmaster.575.be. {} 3600 900 604800 86400",
        serial
    ));

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
