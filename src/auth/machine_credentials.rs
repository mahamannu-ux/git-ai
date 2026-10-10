//! TrackAI machine credentials stored only in the native user credential store.

use std::sync::Arc;
#[cfg(test)]
use std::sync::Mutex;
use zeroize::Zeroize;

#[cfg(all(feature = "keyring", any(target_os = "macos", windows)))]
const SERVICE_NAME: &str = "com.trackai.git-ai.machine";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MachineCredentialStoreCode {
    Available,
    Missing,
    Locked,
    Unsupported,
    Corrupt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineCredentialError {
    pub code: MachineCredentialStoreCode,
}

pub struct MachineCredential {
    value: String,
    key_id: String,
}

impl MachineCredential {
    pub fn parse(mut value: String) -> Result<Self, MachineCredentialError> {
        let key_id = {
            let mut parts = value.split('.');
            match (parts.next(), parts.next(), parts.next(), parts.next()) {
                (Some("trk_v1"), Some(key_id), Some(secret), None)
                    if component(key_id, 16) && component(secret, 43) =>
                {
                    Some(key_id.to_string())
                }
                _ => None,
            }
        };
        match key_id {
            Some(key_id) => Ok(Self { value, key_id }),
            None => {
                value.zeroize();
                Err(corrupt())
            }
        }
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }
    pub fn expose(&self) -> &str {
        &self.value
    }
}

impl Drop for MachineCredential {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

pub trait MachineCredentialStore: Send + Sync {
    fn store(&self, credential: MachineCredential) -> Result<(), MachineCredentialError>;
    fn load(&self, key_id: &str) -> Result<MachineCredential, MachineCredentialError>;
    fn delete(&self, key_id: &str) -> Result<(), MachineCredentialError>;
    fn status(&self) -> MachineCredentialStoreCode;
}

#[derive(Default)]
pub struct NativeMachineCredentialStore;

impl MachineCredentialStore for NativeMachineCredentialStore {
    fn store(&self, credential: MachineCredential) -> Result<(), MachineCredentialError> {
        validate_key_id(credential.key_id())?;
        native_store(credential.key_id(), credential.expose())
    }

    fn load(&self, key_id: &str) -> Result<MachineCredential, MachineCredentialError> {
        validate_key_id(key_id)?;
        let credential = MachineCredential::parse(native_load(key_id)?)?;
        if credential.key_id() != key_id {
            return Err(corrupt());
        }
        Ok(credential)
    }

    fn delete(&self, key_id: &str) -> Result<(), MachineCredentialError> {
        validate_key_id(key_id)?;
        native_delete(key_id)
    }

    fn status(&self) -> MachineCredentialStoreCode {
        if cfg!(any(target_os = "macos", windows)) && cfg!(feature = "keyring") {
            MachineCredentialStoreCode::Available
        } else {
            MachineCredentialStoreCode::Unsupported
        }
    }
}

#[cfg(test)]
#[derive(Default)]
pub struct MemoryMachineCredentialStore {
    values: Mutex<std::collections::HashMap<String, String>>,
}

#[cfg(test)]
impl MachineCredentialStore for MemoryMachineCredentialStore {
    fn store(&self, credential: MachineCredential) -> Result<(), MachineCredentialError> {
        self.values.lock().map_err(|_| locked())?.insert(
            credential.key_id().to_string(),
            credential.expose().to_string(),
        );
        Ok(())
    }
    fn load(&self, key_id: &str) -> Result<MachineCredential, MachineCredentialError> {
        let value = self
            .values
            .lock()
            .map_err(|_| locked())?
            .get(key_id)
            .cloned()
            .ok_or(MachineCredentialError {
                code: MachineCredentialStoreCode::Missing,
            })?;
        MachineCredential::parse(value)
    }
    fn delete(&self, key_id: &str) -> Result<(), MachineCredentialError> {
        if let Some(mut value) = self.values.lock().map_err(|_| locked())?.remove(key_id) {
            value.zeroize();
        }
        Ok(())
    }
    fn status(&self) -> MachineCredentialStoreCode {
        MachineCredentialStoreCode::Available
    }
}

#[cfg(test)]
impl Drop for MemoryMachineCredentialStore {
    fn drop(&mut self) {
        if let Ok(values) = self.values.get_mut() {
            for value in values.values_mut() {
                value.zeroize();
            }
        }
    }
}

pub fn default_machine_credential_store() -> Arc<dyn MachineCredentialStore> {
    Arc::new(NativeMachineCredentialStore)
}

fn validate_key_id(value: &str) -> Result<(), MachineCredentialError> {
    component(value, 16).then_some(()).ok_or_else(corrupt)
}

fn component(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn corrupt() -> MachineCredentialError {
    MachineCredentialError {
        code: MachineCredentialStoreCode::Corrupt,
    }
}
#[cfg(any(test, all(feature = "keyring", any(target_os = "macos", windows))))]
fn locked() -> MachineCredentialError {
    MachineCredentialError {
        code: MachineCredentialStoreCode::Locked,
    }
}

#[cfg(all(feature = "keyring", any(target_os = "macos", windows)))]
fn entry(key_id: &str) -> Result<keyring::Entry, MachineCredentialError> {
    keyring::Entry::new(SERVICE_NAME, key_id).map_err(|_| locked())
}

#[cfg(all(feature = "keyring", any(target_os = "macos", windows)))]
fn native_store(key_id: &str, value: &str) -> Result<(), MachineCredentialError> {
    entry(key_id)?.set_password(value).map_err(|_| locked())
}
#[cfg(not(all(feature = "keyring", any(target_os = "macos", windows))))]
fn native_store(_: &str, _: &str) -> Result<(), MachineCredentialError> {
    Err(MachineCredentialError {
        code: MachineCredentialStoreCode::Unsupported,
    })
}

#[cfg(all(feature = "keyring", any(target_os = "macos", windows)))]
fn native_load(key_id: &str) -> Result<String, MachineCredentialError> {
    match entry(key_id)?.get_password() {
        Ok(value) => Ok(value),
        Err(keyring::Error::NoEntry) => Err(MachineCredentialError {
            code: MachineCredentialStoreCode::Missing,
        }),
        Err(_) => Err(locked()),
    }
}
#[cfg(not(all(feature = "keyring", any(target_os = "macos", windows))))]
fn native_load(_: &str) -> Result<String, MachineCredentialError> {
    Err(MachineCredentialError {
        code: MachineCredentialStoreCode::Unsupported,
    })
}

#[cfg(all(feature = "keyring", any(target_os = "macos", windows)))]
fn native_delete(key_id: &str) -> Result<(), MachineCredentialError> {
    match entry(key_id)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(_) => Err(locked()),
    }
}
#[cfg(not(all(feature = "keyring", any(target_os = "macos", windows))))]
fn native_delete(_: &str) -> Result<(), MachineCredentialError> {
    Err(MachineCredentialError {
        code: MachineCredentialStoreCode::Unsupported,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential() -> String {
        "trk_v1.ABCDEFGHIJKLMNOP.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()
    }

    #[test]
    fn validates_embedded_key_id_without_debugging_secret() {
        let parsed = MachineCredential::parse(credential()).unwrap();
        assert_eq!(parsed.key_id(), "ABCDEFGHIJKLMNOP");
        assert!(!std::any::type_name::<MachineCredential>().is_empty());
        assert!(MachineCredential::parse("trk_v1.short.secret".to_string()).is_err());
    }

    #[test]
    fn memory_store_is_exact_and_missing_is_safe() {
        let store = MemoryMachineCredentialStore::default();
        store
            .store(MachineCredential::parse(credential()).unwrap())
            .unwrap();
        assert_eq!(
            store.load("ABCDEFGHIJKLMNOP").unwrap().key_id(),
            "ABCDEFGHIJKLMNOP"
        );
        store.delete("ABCDEFGHIJKLMNOP").unwrap();
        assert_eq!(
            store.load("ABCDEFGHIJKLMNOP").err().unwrap().code,
            MachineCredentialStoreCode::Missing
        );
    }
}
