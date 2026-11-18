//! uid → username resolution from `/etc/passwd`.
//!
//! Pure std: no libc, no unsafe. The file is read once per scan and cached.

use std::collections::HashMap;
use std::io::{BufRead, BufReader};

#[derive(Debug, Default, Clone)]
pub struct UserTable {
    uid_to_name: HashMap<u32, String>,
}

impl UserTable {
    /// Read `/etc/passwd`. Returns an empty table when the file is unreadable
    /// (non-standard setups, chroots); name resolution then simply stays off.
    pub fn load() -> Self {
        Self::from_path("/etc/passwd").unwrap_or_default()
    }

    fn from_path(path: &str) -> std::io::Result<Self> {
        let file = std::fs::File::open(path)?;
        let reader = BufReader::new(file);
        let mut map = HashMap::new();
        for line in reader.lines() {
            let line = line?;
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            // name:password:uid:gid:gecos:home:shell
            let mut fields = line.split(':');
            let name = match fields.next() {
                Some(n) if !n.is_empty() => n,
                _ => continue,
            };
            let _passwd = fields.next();
            let uid = match fields.next().and_then(|s| s.parse::<u32>().ok()) {
                Some(u) => u,
                None => continue,
            };
            map.insert(uid, name.to_string());
        }
        Ok(Self { uid_to_name: map })
    }

    pub fn name(&self, uid: u32) -> Option<&str> {
        self.uid_to_name.get(&uid).map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_the_system_passwd() {
        let t = UserTable::load();
        assert_eq!(t.name(0), Some("root"), "/etc/passwd must resolve uid 0");
        assert!(t.name(u32::MAX - 1).is_none(), "unknown uid has no name");
    }

    #[test]
    fn malformed_lines_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("passwd");
        std::fs::write(
            &path,
            "# comment line\n\nroot:x:0:0:root:/root:/bin/sh\n:bad:1:1::/:/bin/sh\nbaduid:x:notanumber:0::/:/bin/sh\nnopasswd:5\n",
        )
        .unwrap();

        let t = UserTable::from_path(path.to_str().unwrap()).expect("readable file");
        assert_eq!(t.name(0), Some("root"));
        assert_eq!(t.name(1), None, "empty name is skipped");
        assert_eq!(t.name(5), None, "line without a uid is skipped");
    }

    #[test]
    fn missing_file_is_an_error() {
        assert!(UserTable::from_path("/nonexistent/passwd-for-openfd-test").is_err());
    }

    #[test]
    fn empty_table_resolves_nothing() {
        let t = UserTable::default();
        assert!(t.name(0).is_none());
        assert_eq!(format!("{t:?}"), "UserTable { uid_to_name: {} }");
    }
}
