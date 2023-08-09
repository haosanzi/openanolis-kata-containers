// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

use serde_derive::{Deserialize, Serialize};

/// This struct represents the strongly typed equivalent of the json body
/// from confidential container related requests.
#[derive(Copy, Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub enum TeeType {
    /// Intel Trusted Domain
    TDX = 2,
    /// AMD Secure Encrypted Virtualization (SEV, SEV-ES)
    SEV,
}

/// The microvm state.
///
/// When Dragonball starts, the instance state is Uninitialized. Once start_microvm method is
/// called, the state goes from Uninitialized to Starting. The state is changed to Running until
/// the start_microvm method ends. Halting and Halted are currently unsupported.
#[derive(Copy, Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub enum InstanceState {
    /// Microvm is not initialized.
    Uninitialized,
    /// Microvm is starting.
    #[cfg(not(feature = "sev"))]
    Starting,
    /// Microvm is starting.
    #[cfg(feature = "sev")]
    Starting(VmStartingStage),
    /// Microvm is running.
    Running,
    /// Microvm is Paused.
    Paused,
    /// Microvm received a halt instruction.
    Halting,
    /// Microvm is halted.
    Halted,
    /// Microvm exit instead of process exit.
    Exited(i32),
}

/// Denotes the VM's starting stage. Currently used only when booting an SEV VM.
///
/// When booting an SEV VM,
/// 1. after receiving the `start` data structure, the VMM will measure and
///    encrypt the VM's memory, returning the memory's measurement. At this point,
///    VM is at VmStartingStage::SevMeasured.
/// 2. Then tenant will verify it, generate a secret, and call `start_microvm` again,
/// 3. with which the VMM will continue the subsequent steps of booting the VM
///    (starting vcpus, etc).
///
/// For more information about the SEV booting process, refer to "Launching a
/// Guest" in Appendix A of
/// https://www.amd.com/system/files/TechDocs/55766_SEV-KM_API_Specification.pdf
#[cfg(feature = "sev")]
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum VmStartingStage {
    /// Initial stage
    Initial,
    /// SEV VM memory has already been measured
    SevMeasured,
}

/// The state of async actions
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub enum AsyncState {
    /// Uninitialized
    Uninitialized,
    /// Success
    Success,
    /// Failure
    Failure,
}

/// The strongly typed that contains general information about the microVM.
#[derive(Debug, Deserialize, Serialize)]
pub struct InstanceInfo {
    /// The ID of the microVM.
    pub id: String,
    /// The state of the microVM.
    pub state: InstanceState,
    /// The version of the VMM that runs the microVM.
    pub vmm_version: String,
    /// The pid of the current VMM process.
    pub pid: u32,
    /// The state of async actions.
    pub async_state: AsyncState,
    /// List of tids of vcpu threads (vcpu index, tid)
    pub tids: Vec<(u8, u32)>,
    /// Last instance downtime
    pub last_instance_downtime: u64,
    /// Confidential vm type
    pub confidential_vm_type: Option<TeeType>,
}

impl InstanceInfo {
    /// create instance info object with given id, version, platform type and confidential vm type.
    pub fn new(id: String, vmm_version: String) -> Self {
        InstanceInfo {
            id,
            state: InstanceState::Uninitialized,
            vmm_version,
            pid: std::process::id(),
            async_state: AsyncState::Uninitialized,
            tids: Vec::new(),
            last_instance_downtime: 0,
            confidential_vm_type: None,
        }
    }

    /// return true if VM confidential type is TDX
    pub fn is_tdx_enabled(&self) -> bool {
        matches!(self.confidential_vm_type, Some(TeeType::TDX))
    }

    /// return true if VM confidential type is SEV
    pub fn is_sev_enabled(&self) -> bool {
        matches!(self.confidential_vm_type, Some(TeeType::SEV))
    }

    /// Check if one TEE VM type from the list is enabled.
    #[inline(always)]
    pub fn is_one_of_tee_enabled(&self, tee_list: &[TeeType]) -> bool {
        if tee_list.len() == 0 {
            return false;
        }

        if let Some(tee_type) = self.confidential_vm_type {
            tee_list.iter().any(|&t| t == tee_type)
        } else {
            false
        }
    }
}

impl Default for InstanceInfo {
    fn default() -> Self {
        InstanceInfo {
            id: String::from(""),
            state: InstanceState::Uninitialized,
            vmm_version: env!("CARGO_PKG_VERSION").to_string(),
            pid: std::process::id(),
            async_state: AsyncState::Uninitialized,
            tids: Vec::new(),
            last_instance_downtime: 0,
            confidential_vm_type: None,
        }
    }
}
