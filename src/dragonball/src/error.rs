// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file

//! Error codes for the virtual machine monitor subsystem.

#[cfg(feature = "dbs-virtio-devices")]
use dbs_virtio_devices::Error as VirtIoError;
#[cfg(all(target_arch = "x86_64", feature = "tdx"))]
use dbs_tdx::tdx_ioctls::TdxIoctlError;

use crate::{address_space_manager, device_manager, resource_manager, vcpu, vm};
#[cfg(all(target_arch = "x86_64", feature = "userspace-ioapic"))]
use crate::device_manager::ioapic_dev_mgr::IoapicDeviceMgrError;

/// Shorthand result type for internal VMM commands.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors associated with the VMM internal logic.
///
/// These errors cannot be generated by direct user input, but can result from bad configuration
/// of the host (for example if Dragonball doesn't have permissions to open the KVM fd).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Empty AddressSpace from parameters.
    #[error("Empty AddressSpace from parameters")]
    AddressSpace,

    /// The zero page extends past the end of guest_mem.
    #[error("the guest zero page extends past the end of guest memory")]
    ZeroPagePastRamEnd,

    /// Error writing the zero page of guest memory.
    #[error("failed to write to guest zero page")]
    ZeroPageSetup,

    /// Failure occurs in issuing KVM ioctls and errors will be returned from kvm_ioctls lib.
    #[error("failure in issuing KVM ioctl command: {0}")]
    Kvm(#[source] kvm_ioctls::Error),

    /// The host kernel reports an unsupported KVM API version.
    #[error("unsupported KVM version {0}")]
    KvmApiVersion(i32),

    /// Cannot initialize the KVM context due to missing capabilities.
    #[error("missing KVM capability: {0:?}")]
    KvmCap(kvm_ioctls::Cap),

    #[cfg(target_arch = "x86_64")]
    #[error("failed to configure MSRs: {0:?}")]
    /// Cannot configure MSRs
    GuestMSRs(dbs_arch::msr::Error),

    /// MSR inner error
    #[error("MSR inner error")]
    Msr(vmm_sys_util::fam::Error),

    /// Error writing MP table to memory.
    #[cfg(target_arch = "x86_64")]
    #[error("failed to write MP table to guest memory: {0}")]
    MpTableSetup(#[source] dbs_boot::mptable::Error),

    /// Fail to boot system
    #[error("failed to boot system: {0}")]
    BootSystem(#[source] dbs_boot::Error),

    /// Cannot open the VM file descriptor.
    #[error(transparent)]
    Vm(vm::VmError),

    /// confidential vm type Error
    #[error("confidential-vm-type can only be used in x86_64 now")]
    ConfidentialVmType,
}

/// Errors associated with loading data follow tdshim metadata
#[derive(Debug, thiserror::Error)]
pub enum LoadTdDataError {
    /// Failed to get hob address
    #[error("failed to get hob address from tdshim metadata")]
    HobOffset,
    /// Failed to get payload address
    #[error("failed to get payload address from tdshim metadata")]
    PayloadOffset,
    /// Failed to get payload param address
    #[error("failed to get payload params address from tdshim metadata")]
    PayloadParamsOffset,
    /// Failed to parse tdshim data
    #[error("failed to parse tdshim data: {0}")]
    ParseTdshim(#[source] dbs_tdx::td_shim::metadata::TdvfError),
    /// Failed to read tdshim data
    #[error("failed to read tdshim data: {0}")]
    ReadTdshim(#[source] std::io::Error),
    /// Failed to load data to guest memory
    #[error("failed to load data to guest memory: {0}")]
    LoadData(#[source] vm_memory::GuestMemoryError),
    /// Failed to load payload
    #[error("failed to load tdshim data")]
    LoadPayload,
}
/// Errors associated with starting the instance.
#[derive(Debug, thiserror::Error)]
pub enum StartMicroVmError {
    /// Failed to allocate resources.
    #[error("cannot allocate resources")]
    AllocateResource(#[source] resource_manager::ResourceError),

    /// Cannot read from an Event file descriptor.
    #[error("failure while reading from EventFd file descriptor")]
    EventFd,

    /// Cannot add event to Epoll.
    #[error("failure while registering epoll event for file descriptor")]
    RegisterEvent,

    /// The start command was issued more than once.
    #[error("the virtual machine is already running")]
    MicroVMAlreadyRunning,

    /// Cannot start the VM because the kernel was not configured.
    #[error("cannot start the virtual machine without kernel configuration")]
    MissingKernelConfig,

    #[cfg(feature = "hotplug")]
    /// Upcall initialize miss vsock device.
    #[error("the upcall client needs a virtio-vsock device for communication")]
    UpcallMissVsock,

    /// Upcall is not ready
    #[error("the upcall client is not ready")]
    UpcallNotReady,

    /// Configuration passed in is invalidate.
    #[error("invalid virtual machine configuration: {0} ")]
    ConfigureInvalid(String),

    /// This error is thrown by the minimal boot loader implementation.
    /// It is related to a faulty memory configuration.
    #[error("failure while configuring boot information for the virtual machine: {0}")]
    ConfigureSystem(#[source] Error),

    /// Cannot configure the VM.
    #[error("failure while configuring the virtual machine: {0}")]
    ConfigureVm(#[source] vm::VmError),

    /// Cannot load initrd.
    #[error("cannot load Initrd into guest memory: {0}")]
    InitrdLoader(#[from] LoadInitrdError),

    /// Cannot load kernel due to invalid memory configuration or invalid kernel image.
    #[error("cannot load guest kernel into guest memory: {0}")]
    KernelLoader(#[source] linux_loader::loader::Error),

    /// Cannot load command line string.
    #[error("failure while configuring guest kernel commandline: {0}")]
    LoadCommandline(#[source] linux_loader::loader::Error),

    /// Cannot process command line string.
    #[error("failure while processing guest kernel commandline: {0}.")]
    ProcessCommandlne(#[source] linux_loader::cmdline::Error),

    /// The device manager was not configured.
    #[error("the device manager failed to manage devices: {0}")]
    DeviceManager(#[source] device_manager::DeviceMgrError),

    /// Cannot add devices to the Legacy I/O Bus.
    #[error("failure in managing legacy device: {0}")]
    LegacyDevice(#[source] device_manager::LegacyDeviceError),

    #[cfg(feature = "virtio-vsock")]
    /// Failed to create the vsock device.
    #[error("cannot create virtio-vsock device: {0}")]
    CreateVsockDevice(#[source] VirtIoError),

    #[cfg(feature = "virtio-vsock")]
    /// Cannot initialize a MMIO Vsock Device or add a device to the MMIO Bus.
    #[error("failure while registering virtio-vsock device: {0}")]
    RegisterVsockDevice(#[source] device_manager::DeviceMgrError),

    /// Address space manager related error, e.g.cannot access guest address space manager.
    #[error("address space manager related error: {0}")]
    AddressManagerError(#[source] address_space_manager::AddressManagerError),

    /// Cannot create a new vCPU file descriptor.
    #[error("vCPU related error: {0}")]
    Vcpu(#[source] vcpu::VcpuManagerError),

    #[cfg(all(feature = "hotplug", feature = "dbs-upcall"))]
    /// Upcall initialize Error.
    #[error("failure while initializing the upcall client: {0}")]
    UpcallInitError(#[source] dbs_upcall::UpcallClientError),

    #[cfg(all(feature = "hotplug", feature = "dbs-upcall"))]
    /// Upcall connect Error.
    #[error("failure while connecting the upcall client: {0}")]
    UpcallConnectError(#[source] dbs_upcall::UpcallClientError),

    #[cfg(feature = "virtio-blk")]
    /// Virtio-blk errors.
    #[error("virtio-blk errors: {0}")]
    BlockDeviceError(#[source] device_manager::blk_dev_mgr::BlockDeviceError),

    #[cfg(feature = "virtio-net")]
    /// Virtio-net errors.
    #[error("virtio-net errors: {0}")]
    VirtioNetDeviceError(#[source] device_manager::virtio_net_dev_mgr::VirtioNetDeviceError),

    #[cfg(feature = "virtio-fs")]
    /// Virtio-fs errors.
    #[error("virtio-fs errors: {0}")]
    FsDeviceError(#[source] device_manager::fs_dev_mgr::FsDeviceError),

    /// TDX ioctl related error.
     #[cfg(all(target_arch = "x86_64", feature = "tdx"))]
     #[error("TDX ioctl related error.")]
     TdxIoctlError(#[source] TdxIoctlError),

    /// TDX not supported
    #[error("Dragonball without TDX support.")]
    TdxError,

    /// Cannot load td data
    #[cfg(all(target_arch = "x86_64", feature = "tdx"))]
    #[error("cannot load td data following tdshim metadata: {0}")]
    TdDataLoader(#[source] self::LoadTdDataError),

    /// Cannot access guest address space manager.
    #[error("cannot access guest address space manager: {0}")]
    GuestMemory(#[source] address_space_manager::AddressManagerError),


    /// Ioapic Device Errors
    #[cfg(all(target_arch = "x86_64", feature = "userspace-ioapic"))]
    #[error("ioapic device: {0}")]
    IoapicDevice(IoapicDeviceMgrError),
    /// Missing Ioapic device
    #[cfg(all(target_arch = "x86_64", feature = "userspace-ioapic"))]
    #[error("missing Ioapic device: {0}")]
    MissingIoapicDevice(std::io::Error),
}

/// Errors associated with starting the instance.
#[derive(Debug, thiserror::Error)]
pub enum StopMicrovmError {
    /// Guest memory has not been initialized.
    #[error("Guest memory has not been initialized")]
    GuestMemoryNotInitialized,

    /// Cannnot remove devices
    #[error("Failed to remove devices in device_manager {0}")]
    DeviceManager(#[source] device_manager::DeviceMgrError),
}

/// Errors associated with loading initrd
#[derive(Debug, thiserror::Error)]
pub enum LoadInitrdError {
    /// Cannot load initrd due to an invalid memory configuration.
    #[error("failed to load the initrd image to guest memory")]
    LoadInitrd,
    /// Cannot load initrd due to an invalid image.
    #[error("failed to read the initrd image: {0}")]
    ReadInitrd(#[source] std::io::Error),
}

/// A dedicated error type to glue with the vmm_epoll crate.
#[derive(Debug, thiserror::Error)]
pub enum EpollError {
    /// Generic internal error.
    #[error("unclassfied internal error")]
    InternalError,

    /// Errors from the epoll subsystem.
    #[error("failed to issue epoll syscall: {0}")]
    EpollMgr(#[from] dbs_utils::epoll_manager::Error),

    /// Generic IO errors.
    #[error(transparent)]
    IOError(std::io::Error),

    #[cfg(feature = "dbs-virtio-devices")]
    /// Errors from virtio devices.
    #[error("failed to manager Virtio device: {0}")]
    VirtIoDevice(#[source] VirtIoError),
}
