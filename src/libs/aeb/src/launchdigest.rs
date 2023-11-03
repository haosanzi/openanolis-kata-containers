use anyhow::{anyhow, bail, Context, Result};
use sm3::{Digest, Sm3};
use std::convert::TryInto;
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::Path;

use crate::kbs::GuestPreAttestationConfig;

use crate::tdvf::{parse_tdvf_sections, TdvfSectionType};

const BLOCK_SIZE: usize = 16;
const CMDLINE_SIZE: usize = 4 * 1024;
const TD_HOB_SIZE: usize = 128 * 1024;

fn hash_data(algorithm: &str, data: &[u8]) -> Result<[u8; 32]> {
    match algorithm {
        "sha256" => {
            let mut hasher = openssl::sha::Sha256::new();
            hasher.update(data);
            Ok(hasher.finish())
        }
        "sm3" => {
            let mut hasher = Sm3::new();
            hasher.update(data);
            Ok(hasher.finalize().to_vec().try_into().unwrap())
        }
        _ => Err(anyhow!("Unsupported algorithm: {}", algorithm)),
    }
}

pub fn calculate_launch_digest(
    mode: &str,
    firmware_path: &Path,
    kernel_path: &Path,
    mut cmdline: Vec<u8>,
    mut td_hob: Vec<u8>,
) -> Result<[u8; 32]> {
    // 1. BFV & CFV from firmware file
    let mut firmware_file = File::open(firmware_path)?;
    let tdvf_sections = parse_tdvf_sections(&mut firmware_file)?;

    let mut bfv_region: Option<(u64, usize)> = None;
    let mut cfv_region: Option<(u64, usize)> = None;
    for s in tdvf_sections {
        match s.r#type {
            TdvfSectionType::Bfv => {
                bfv_region = Some((s.data_offset as u64, s.data_size as usize));
            }
            TdvfSectionType::Cfv => {
                cfv_region = Some((s.data_offset as u64, s.data_size as usize));
            }
            _ => {}
        }
    }
    let bfv_region = bfv_region.context("BFV not found in firmware")?;
    let cfv_region = cfv_region.context("CFV not found in firmware")?;

    let mut bfv = vec![0; bfv_region.1];
    let mut cfv = vec![0; cfv_region.1];
    firmware_file.read_exact_at(&mut bfv, bfv_region.0)?;
    firmware_file.read_exact_at(&mut cfv, cfv_region.0)?;

    // 2. kernel
    let mut kernel = std::fs::read(kernel_path).context("failed to read kernel file")?;
    let remainder = kernel.len() % BLOCK_SIZE;
    if remainder != 0 {
        let padded_size = kernel.len() + BLOCK_SIZE - remainder;
        kernel.resize(padded_size, 0);
    }

    // 3. cmdline
    if cmdline.len() > CMDLINE_SIZE {
        bail!("cmdline is too large");
    }
    cmdline.resize(CMDLINE_SIZE, 0);

    // 4. tdhob
    if td_hob.len() > TD_HOB_SIZE {
        bail!("td_hob is too large");
    }
    td_hob.resize(TD_HOB_SIZE, 0);

    let content: Vec<u8> = vec![&bfv, &cfv, &kernel, &cmdline, &td_hob]
        .into_iter()
        .flatten()
        .copied()
        .collect();

    let output = match mode {
        "sev" => hash_data("sha256", &content)?,
        "csv" => hash_data("sm3", &content)?,
        _ => return Err(anyhow!("Only support sev or csv mode")),
    };

    Ok(output)
}

// For more info, see AMD SEV API document 55766
const SEV_POLICY_BIT_SEV_ES: u32 = 0x4;

pub fn calculate_guest_launch_digest(config: &GuestPreAttestationConfig) -> Result<[u8; 32]> {
    // SEV-ES guest
    if config.policy & SEV_POLICY_BIT_SEV_ES != 0 {
        // TODO
        // calculate_sev_es_launch_digest
    }

    let tdhob: Vec<u8> = config.tdhob.clone();
    let cmdline: Vec<u8> = config.cmdline.clone();

    // SEV guest
    calculate_launch_digest(
        "sev",
        config.firmware.clone().unwrap().as_ref(),
        config.kernel.clone().unwrap().as_ref(),
        cmdline,
        tdhob,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sev_calculate_launch_digest() {
        let firmware_path = Path::new("./test/final-wzy-int3.bin");
        let kernel_path = Path::new("./test/bzImage");
        let cmdline: Vec<u8> = std::fs::read("./test/cmdline").unwrap();
        let tdhob: Vec<u8> = std::fs::read("./test/tdhob").unwrap();

        let sev_output = hex::encode(
            calculate_launch_digest("sev", firmware_path, kernel_path, cmdline, tdhob).unwrap(),
        );
        let sev_expected =
            "a03720ea72dbb7054b704d2220c853de1518889c9d568cb7811cf46b42e909fb".to_string();

        assert_eq!(sev_expected, sev_output);
    }

    #[test]
    fn test_csv_calculate_launch_digest() {
        let firmware_path = Path::new("./test/final-wzy-int3.bin");
        let kernel_path = Path::new("./test/bzImage");
        let cmdline: Vec<u8> = std::fs::read("./test/cmdline").unwrap();
        let tdhob: Vec<u8> = std::fs::read("./test/tdhob").unwrap();

        let csv_output = hex::encode(
            calculate_launch_digest("csv", firmware_path, kernel_path, cmdline, tdhob).unwrap(),
        );

        let csv_expected =
            "82dd12ce1d080c46c4d2e01db61a3c9d20a10d2d43d39160a97e84f6dfefe434".to_string();

        assert_eq!(csv_expected, csv_output);
    }
}
