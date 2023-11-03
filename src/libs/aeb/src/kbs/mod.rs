#[derive(Default, Debug)]
pub struct GuestPreAttestationConfig {
    pub proxy: String,
    pub keyset: String,
    pub launch_id: String,

    pub firmware: Option<String>,
    pub kernel: Option<String>,
    pub initrd: Option<String>,
    pub cmdline: Vec<u8>,
    pub tdhob: Vec<u8>,

    pub cert_chain_path: String,
    pub key_broker_secret_type: String,
    pub key_broker_secret_guid: String,
    pub policy: u32,

    pub num_vcpu: u8,
}
