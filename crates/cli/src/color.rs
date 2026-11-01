//! ANSI colors for human-facing output. Machine formats (JSON, CSV, terse)
//! never get colors. Controlled by `--color auto|always|never` and disabled
//! when stdout is not a terminal (NO_COLOR honored).

use std::io::IsTerminal;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorMode {
    Auto,
    Always,
    Never,
}

impl ColorMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "auto" => Some(ColorMode::Auto),
            "always" => Some(ColorMode::Always),
            "never" => Some(ColorMode::Never),
            _ => None,
        }
    }

    pub fn effective(self) -> bool {
        match self {
            ColorMode::Always => true,
            ColorMode::Never => false,
            ColorMode::Auto => {
                !std::env::var_os("NO_COLOR").is_some() && std::io::stdout().is_terminal()
            }
        }
    }
}

const RED: &str = "\x1b[31m";
const CYAN: &str = "\x1b[36m";
const MAGENTA: &str = "\x1b[35m";
const YELLOW: &str = "\x1b[33m";
const GREEN: &str = "\x1b[32m";
const RESET: &str = "\x1b[0m";

/// Wraps text in ANSI color when colors are enabled; identity otherwise.
#[derive(Debug, Clone, Copy)]
pub struct Colors {
    pub enabled: bool,
}

impl Colors {
    pub fn new(enabled: bool) -> Self {
        Colors { enabled }
    }

    fn wrap(&self, code: &str, text: &str) -> String {
        if self.enabled {
            format!("{code}{text}{RESET}")
        } else {
            text.to_string()
        }
    }

    pub fn tcp(&self, text: &str) -> String {
        self.wrap(CYAN, text)
    }

    pub fn udp(&self, text: &str) -> String {
        self.wrap(MAGENTA, text)
    }

    pub fn unix(&self, text: &str) -> String {
        self.wrap(YELLOW, text)
    }

    pub fn deleted(&self, text: &str) -> String {
        self.wrap(RED, text)
    }

    pub fn opened(&self, text: &str) -> String {
        self.wrap(GREEN, text)
    }

    pub fn closed(&self, text: &str) -> String {
        self.wrap(RED, text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_modes() {
        assert_eq!(ColorMode::parse("always"), Some(ColorMode::Always));
        assert_eq!(ColorMode::parse("NEVER"), Some(ColorMode::Never));
        assert_eq!(ColorMode::parse("auto"), Some(ColorMode::Auto));
        assert_eq!(ColorMode::parse("bogus"), None);
    }

    #[test]
    fn disabled_colors_are_identity() {
        let c = Colors::new(false);
        assert_eq!(c.tcp("TCP"), "TCP");
        assert_eq!(c.deleted("/x (deleted)"), "/x (deleted)");
    }

    #[test]
    fn enabled_colors_wrap() {
        let c = Colors::new(true);
        assert_eq!(c.tcp("TCP"), "\x1b[36mTCP\x1b[0m");
    }
}
