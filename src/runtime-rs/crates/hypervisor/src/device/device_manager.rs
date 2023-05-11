// Copyright (c) 2019-2023 Alibaba Cloud
// Copyright (c) 2019-2023 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{collections::HashMap, sync::Arc};

use anyhow::{anyhow, Context, Result};
use kata_sys_util::rand::RandomBytes;
use tokio::sync::Mutex;

use crate::{
    BlockConfig, Device, DeviceConfig, Hypervisor, KATA_BLK_DEV_TYPE, KATA_MMIO_BLK_DEV_TYPE,
    VIRTIO_BLOCK_MMIO, VIRTIO_BLOCK_PCI,
};

use super::util::{get_host_path, get_virt_drive_name};
pub type ArcBoxDevice = Arc<Mutex<Box<dyn Device>>>;

/// block_index and released_block_index are used to search an available block index
/// in Sandbox.
///
/// @block_index generally default is 1 for <vdb>;
/// @released_block_index for blk devices removed and indexes will released at the same time.
#[derive(Clone, Debug, Default)]
struct SharedInfo {
    block_index: u64,
    released_block_index: Vec<u64>,
}

impl SharedInfo {
    fn new(index: u64) -> Self {
        SharedInfo {
            block_index: index,
            released_block_index: vec![],
        }
    }

    // declare the available block index
    fn declare_device_index(&mut self) -> Result<u64> {
        let current_index = if let Some(index) = self.released_block_index.pop() {
            index
        } else {
            self.block_index
        };
        self.block_index += 1;

        Ok(current_index)
    }

    fn release_device_index(&mut self, index: u64) {
        self.released_block_index.push(index);
        self.released_block_index.sort_by(|a, b| b.cmp(a));
    }
}

// Device manager will manage the lifecycle of sandbox device
pub struct DeviceManager {
    devices: HashMap<String, Arc<Mutex<Box<dyn Device>>>>,
    hypervisor: Arc<dyn Hypervisor>,
    shared_info: SharedInfo,
}

impl DeviceManager {
    pub fn new(hypervisor: Arc<dyn Hypervisor>) -> Result<Self> {
        let devices = HashMap::<String, Arc<Mutex<Box<dyn Device>>>>::new();
        Ok(DeviceManager {
            devices,
            hypervisor,
            shared_info: SharedInfo::new(1),
        })
    }

    pub async fn new_device(&mut self, device_config: &DeviceConfig) -> Result<String> {
        let device_id = if let Some(dev) = self.find_device(device_config).await {
            dev
        } else {
            self.create_device(device_config)
                .await
                .context("failed to create device")?
        };
        Ok(device_id)
    }

    pub async fn try_add_device(&mut self, device_id: &String) -> Result<()> {
        let device = self
            .devices
            .get_mut(device_id)
            .context("failed to find device")?;
        // increase attach count, skip attach the device if the device is already attached
        let need_skip = device
            .lock()
            .await
            .increase_attach_count()
            .await
            .context("failed to increase attach count")?;
        if need_skip {
            return Ok(());
        }
        let result = device.lock().await.attach(self.hypervisor.as_ref()).await;
        // handle attach error
        if let Err(e) = result {
            device.lock().await.decrease_attach_count().await?;
            if let DeviceConfig::Block(config) = device.lock().await.get_device_info().await {
                self.shared_info.release_device_index(config.index);
            };
            self.devices.remove(device_id);
            return Err(e);
        }
        Ok(())
    }

    pub async fn try_remove_device(&mut self, device_id: &str) -> Result<()> {
        if let Some(dev) = self.devices.get(device_id) {
            // get the count of device detached, skip detach once it reaches the 0.
            let skip = dev.lock().await.decrease_attach_count().await?;
            if skip {
                return Ok(());
            }
            let result = match dev.lock().await.detach(self.hypervisor.as_ref()).await {
                Ok(index) => {
                    if let Some(i) = index {
                        // release the declared block device index
                        self.shared_info.release_device_index(i);
                    }
                    Ok(())
                }
                Err(e) => {
                    dev.lock().await.increase_attach_count().await?;
                    Err(e)
                }
            };
            if result.is_ok() {
                // if detach success, remove it from device manager
                self.devices.remove(device_id);
            }
            return result;
        }
        Err(anyhow!(
            "device with specified ID hasn't been created. {}",
            device_id
        ))
    }

    pub async fn get_device_info(&self, device_id: &String) -> Result<DeviceConfig> {
        if let Some(dev) = self.devices.get(device_id) {
            return Ok(dev.lock().await.get_device_info().await);
        }
        Err(anyhow!(
            "device with specified ID hasn't been created. {}",
            device_id
        ))
    }

    async fn find_device(&self, device_config: &DeviceConfig) -> Option<String> {
        for (device_id, dev) in &self.devices {
            match dev.lock().await.get_device_info().await {
                DeviceConfig::Block(config) => match device_config {
                    DeviceConfig::Block(ref config_new) => {
                        if config_new.path_on_host == config.path_on_host {
                            return Some(device_id.to_string());
                        }
                    }
                    _ => {
                        continue;
                    }
                },
                _ => {
                    // TODO: support find other device type
                    continue;
                }
            }
        }
        None
    }

    async fn create_device(&mut self, device_config: &DeviceConfig) -> Result<String> {
        // device ID must be generated by manager instead of device itself
        // in case of ID collision
        let device_id = self.new_device_id()?;
        let dev: ArcBoxDevice = match device_config {
            DeviceConfig::Block(config) => {
                let mut block_config = config.clone();
                block_config.id = device_id.clone();
                // get hypervisor block driver
                let block_driver = match self
                    .hypervisor
                    .hypervisor_config()
                    .await
                    .blockdev_info
                    .block_device_driver
                    .as_str()
                {
                    // convert the block driver to kata type
                    VIRTIO_BLOCK_MMIO => KATA_MMIO_BLK_DEV_TYPE.to_string(),
                    VIRTIO_BLOCK_PCI => KATA_BLK_DEV_TYPE.to_string(),
                    _ => "".to_string(),
                };
                block_config.driver_option = block_driver;
                // generate virt path
                let current_index = self.shared_info.declare_device_index()?;
                block_config.index = current_index;
                let drive_name = get_virt_drive_name(current_index as i32)?;
                block_config.virt_path = format!("/dev/{}", drive_name);
                // get device host path
                block_config.path_on_host =
                    get_host_path("b".to_owned(), config.major, config.minor)
                        .context("failed to get host path")?;
                Arc::new(Mutex::new(Box::new(BlockConfig::new(block_config))))
            }
            _ => {
                return Err(anyhow!("invliad device type"));
            }
        };
        // register device to devices
        self.devices.insert(device_id.clone(), dev.clone());
        Ok(device_id)
    }

    // device ID must be generated by device manager instead of device itself
    // in case of ID collision
    fn new_device_id(&self) -> Result<String> {
        for _ in 0..5 {
            let rand_bytes = RandomBytes::new(8);
            let id = format!("{:x}", rand_bytes);

            // check collision in devices
            if self.devices.get(&id).is_none() {
                return Ok(id);
            }
        }

        Err(anyhow!("ID are exhausted"))
    }
}
