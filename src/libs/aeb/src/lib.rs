use anyhow::{anyhow, Result};
use codicon::{Decoder, Encoder};
use log::*;
use sev::{
    certs::sev::sev::Certificate,
    launch::sev::{Header, Measurement, Secret, Session, Start},
};
use std::io::Cursor;

use crate::grpc::key_broker::{
    key_broker_service_client::KeyBrokerServiceClient, BundleRequest, RequestDetails, SecretRequest,
};
use crate::kbs::GuestPreAttestationConfig;

mod firmware;
mod grpc;
pub mod kbs;
mod launchdigest;
mod tdvf;

// setup prelaunch attestation for AMD SEV guests
pub async fn setup_sevguest_pre_attestation(
    config: &GuestPreAttestationConfig,
) -> Result<(String, Start)> {
    info!("Set up prelaunch attestation");

    let policy = config.policy;
    let cert_chain_path = config.cert_chain_path.clone();
    let proxy = config.proxy.clone();

    let cert_chain_bin = std::fs::read(cert_chain_path.clone())
        .unwrap_or_else(|_| panic!("failed to read cert_chain"));
    let cert_chain = base64::encode(cert_chain_bin);

    // gRPC connection
    let mut client = KeyBrokerServiceClient::connect(proxy.clone())
        .await
        .expect("failed to connect to attestation proxy");

    let request = tonic::Request::new(BundleRequest {
        certificate_chain: cert_chain,
        policy,
    });
    let response = client
        .get_bundle(request)
        .await
        .expect("failed to receiving launch bundle from attestation proxy")
        .into_inner();

    let attestation_id = response.launch_id.clone();
    if attestation_id.is_empty() {
        return Err(anyhow!("Failed to decode key"));
    }

    let godh_bytes = base64::decode(response.guest_owner_public_key.as_bytes()).unwrap();
    let session_byte = base64::decode(response.launch_blob.as_bytes()).unwrap();

    let godh_cert = Certificate::decode(&godh_bytes[..], ())
        .map_err(|e| anyhow!("GODH Cert can not formatted correctly: {}", e))?;
    let session: Session = bincode::deserialize(&session_byte)
        .map_err(|e| anyhow!("Launch blob can not formatted correctly: {}", e))?;

    Ok((
        attestation_id,
        Start {
            policy: policy.into(),
            cert: godh_cert,
            session,
        },
    ))
}

// wait for prelaunch attestation to complete
pub async fn sev_guest_pre_attestation(
    config: &GuestPreAttestationConfig,
    launch_measurement: Measurement,
) -> Result<Secret> {
    info!("SEV attestation: Set up prelaunch attestation");

    // gRPC connection
    let mut client = KeyBrokerServiceClient::connect(config.proxy.clone())
        .await
        .expect("failed to connect to key broker service");

    let request_details = RequestDetails {
        guid: config.key_broker_secret_guid.clone(),
        format: "JSON".to_string(),
        secret_type: config.key_broker_secret_type.clone(),
        id: config.keyset.clone(),
    };

    let launch_digest =
        launchdigest::calculate_guest_launch_digest(config).expect("failed to get launch digest");
    let launch_digest_base64 = base64::encode(launch_digest);

    println!("launch_digest is {:?}", launch_digest);
    println!("launch_digest_base64 is {:?}", launch_digest_base64);

    let build = firmware::platform_status().unwrap().build;

    let mut binary_measure = Cursor::new(Vec::new());
    launch_measurement.encode(&mut binary_measure, ())?;
    let measurement = base64::encode(binary_measure.into_inner());

    let request = tonic::Request::new(SecretRequest {
        launch_measurement: measurement,
        launch_id: config.launch_id.clone(), // stored from bundle request
        policy: config.policy,               // stored from startup
        api_major: build.version.major as u32,
        api_minor: build.version.minor as u32,
        build_id: build.build as u32,
        fw_digest: launch_digest_base64,
        launch_description: "shim launch".to_string(),
        secret_requests: vec![request_details],
    });

    info!("requesting secrets");
    let response = client.get_secret(request).await.unwrap().into_inner();

    let secret_header_byte = base64::decode(response.launch_secret_header).unwrap();
    let secret_header: Header = bincode::deserialize(&secret_header_byte)?;
    let secret_data = base64::decode(response.launch_secret_data).unwrap();

    Ok(Secret {
        header: secret_header,
        ciphertext: secret_data,
    })
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     const TEST_OVMF_PATH: &str = "src/testdata/ovmf_suffix.bin";
//     const TEST_DATA: &str = "/dev/null";
//     const CERT_CHAIN_PATH: &str = "src/testdata/cert_chain.cert";

//     #[test]
//     fn test_sev_guest_pre_attestation() {
//         let mut config = GuestPreAttestationConfig {
//             proxy: "http://30.97.44.97:44444".to_string(),
//             keyset: "KEYSET-1".to_string(),
//             launch_id: "c82fcd1b-ffcb-4a78-b091-98e005a18faf".to_string(),
//             firmware: Some(TEST_OVMF_PATH.into()),
//             kernel: Some(TEST_DATA.into()),
//             initrd: Some(TEST_DATA.into()),
//             cmdline: Some(TEST_DATA.into()),
//             cert_chain_path: CERT_CHAIN_PATH.to_string(),
//             key_broker_secret_type: "bundle".to_string(),
//             key_broker_secret_guid: "e6f5a162-d67f-4750-a67c-5d065f2a9910".to_string(),
//             policy: 0,
//             num_vcpu: 1,
//         };

//         let (sev_attestation_id, _start) =
//             async_std::task::block_on(async { setup_sevguest_pre_attestation(&config).await })
//                 .map_err(|error| {
//                     error!("SEV attestation setup failed {:?}", error);
//                     error
//                 })
//                 .unwrap();

//         // println!("attestation id is {:?}", sev_attestation_id);
//         // println!("start is {:?}", start);

//         config.launch_id = sev_attestation_id;
//         let launch_measurement = Measurement {
//             measure: [0u8; 32],
//             mnonce: [0u8; 16],
//         };

//         let tdhob: Vec<u8> = Vec::new();

//         let _secret = async_std::task::block_on(async {
//             sev_guest_pre_attestation(&config, launch_measurement, tdhob).await
//         })
//         .map_err(|error| {
//             error!("SEV attestation setup failed {:?}", error);
//             error
//         })
//         .unwrap();
//         // println!("secret is {:?}", secret);
//     }
// }
