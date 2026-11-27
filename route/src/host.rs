//! The key-value store and clock, behind one indirection.
//!
//! Under `cfg(test)` these resolve to an in-process fake instead of the host.
//! Some invariants in `workflow` are about the order two writes land in, and
//! about what a retry reads when the first lands and the second does not.
//! Neither is visible from outside the store, so without a fake store they
//! cannot be tested at all — which is how the approval write order came to be
//! documented by a comment that no longer matched the code.
//!
//! Only the store and the clock are faked. Signing and HTTP are not, so the
//! tests this enables drive the state machine directly rather than a whole
//! route.

#[cfg(test)]
pub use fake::*;
#[cfg(not(test))]
pub use real::*;

#[cfg(not(test))]
mod real {
    use petal::SdkError;

    pub fn store_get(key: &str, max_bytes: usize) -> Result<Vec<u8>, SdkError> {
        petal::sdk::store_get(key, max_bytes)
    }
    pub fn store_put(key: &str, value: &[u8], secret: bool) -> Result<(), SdkError> {
        petal::sdk::store_put(key, value, secret)
    }
    pub fn store_put_new(key: &str, value: &[u8], secret: bool) -> Result<(), SdkError> {
        petal::sdk::store_put_new(key, value, secret)
    }
    pub fn store_del(key: &str) -> Result<(), SdkError> {
        petal::sdk::store_del(key)
    }
    pub fn store_list(prefix: &str, max_bytes: usize) -> Result<Vec<String>, SdkError> {
        petal::sdk::store_list(prefix, max_bytes)
    }
    pub fn now_ms() -> u64 {
        petal::sdk::now_ms()
    }
}

#[cfg(test)]
mod fake {
    use petal::{HostStatus, SdkError};
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    #[derive(Default)]
    pub struct FakeHost {
        values: BTreeMap<String, Vec<u8>>,
        /// Any write whose key contains this fails, standing in for a store
        /// that accepted one write of a pair and not the other.
        fail_writes_matching: Option<String>,
        now_ms: u64,
    }

    thread_local! {
        static HOST: RefCell<FakeHost> = RefCell::new(FakeHost {
            now_ms: 1_700_000_000_000,
            ..FakeHost::default()
        });
    }

    fn with<T>(f: impl FnOnce(&mut FakeHost) -> T) -> T {
        HOST.with(|host| f(&mut host.borrow_mut()))
    }

    /// Empties the store. Each test starts from here; the fake is
    /// thread-local, so tests do not share it.
    pub fn test_reset() {
        with(|host| {
            host.values.clear();
            host.fail_writes_matching = None;
        });
    }

    /// Makes every write whose key contains `needle` fail.
    pub fn test_fail_writes_matching(needle: Option<&str>) {
        with(|host| host.fail_writes_matching = needle.map(str::to_owned));
    }

    fn refuse(host: &FakeHost, key: &str) -> bool {
        host.fail_writes_matching
            .as_ref()
            .is_some_and(|needle| key.contains(needle.as_str()))
    }

    pub fn store_get(key: &str, _max_bytes: usize) -> Result<Vec<u8>, SdkError> {
        with(|host| {
            host.values
                .get(key)
                .cloned()
                .ok_or(SdkError::Host(HostStatus::NotFound))
        })
    }

    pub fn store_put(key: &str, value: &[u8], _secret: bool) -> Result<(), SdkError> {
        with(|host| {
            if refuse(host, key) {
                return Err(SdkError::Message(format!("injected write failure: {key}")));
            }
            host.values.insert(key.to_owned(), value.to_vec());
            Ok(())
        })
    }

    /// Create-only, as the host's is: an existing key is refused. The lost
    /// race in `owner_nonce` depends on this.
    pub fn store_put_new(key: &str, value: &[u8], _secret: bool) -> Result<(), SdkError> {
        with(|host| {
            if host.values.contains_key(key) {
                return Err(SdkError::Host(HostStatus::Invalid));
            }
            if refuse(host, key) {
                return Err(SdkError::Message(format!("injected write failure: {key}")));
            }
            host.values.insert(key.to_owned(), value.to_vec());
            Ok(())
        })
    }

    pub fn store_del(key: &str) -> Result<(), SdkError> {
        with(|host| {
            host.values.remove(key);
            Ok(())
        })
    }

    pub fn store_list(prefix: &str, _max_bytes: usize) -> Result<Vec<String>, SdkError> {
        with(|host| {
            Ok(host
                .values
                .keys()
                .filter(|key| key.starts_with(prefix))
                .cloned()
                .collect())
        })
    }

    pub fn now_ms() -> u64 {
        with(|host| host.now_ms)
    }
}
