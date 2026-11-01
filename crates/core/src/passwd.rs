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
