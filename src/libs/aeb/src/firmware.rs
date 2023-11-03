use anyhow::{anyhow, Context, Result};

use sev::firmware::host::Firmware;
use sev::firmware::host::Status;

fn firmware() -> Result<Firmware> {
    Firmware::open().context("unable to open /dev/sev")
}

pub fn platform_status() -> Result<Status> {
    firmware()?
        .platform_status()
        .map_err(|e| anyhow!(format!("{:?}", e)))
        .context("unable to fetch platform status")
}

#[cfg(test)]
mod tests {
    use super::*;
    use sev::{Build, Version};

    #[test]
    fn test_platform_status() {
        let status = platform_status().unwrap();
        assert!(
            status.build
                > Build {
                    version: Version {
                        major: 1,
                        minor: 49
                    },
                    ..Default::default()
                }
        );
    }
}
