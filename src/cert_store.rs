//! Bindings to winapi's certificate-store related APIs.

use crypt32;
use std::ffi::OsStr;
use std::fmt;
use std::io;
use std::os::windows::prelude::*;
use std::ptr;
use winapi;

use cert_context::CertContext;
use ctl_context::CtlContext;

use Inner;

/// Representation of certificate store on Windows, wrapping a `HCERTSTORE`.
pub struct CertStore(winapi::HCERTSTORE);

unsafe impl Sync for CertStore {}
unsafe impl Send for CertStore {}

impl fmt::Debug for CertStore {
	fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
		fmt.debug_struct("CertStore").finish()
	}
}

impl Drop for CertStore {
    fn drop(&mut self) {
        unsafe {
            crypt32::CertCloseStore(self.0, 0);
        }
    }
}

impl Clone for CertStore {
    fn clone(&self) -> CertStore {
        unsafe { CertStore(crypt32::CertDuplicateStore(self.0)) }
    }
}

impl Inner<winapi::HCERTSTORE> for CertStore {
    unsafe fn from_inner(t: winapi::HCERTSTORE) -> CertStore {
        CertStore(t)
    }

    fn as_inner(&self) -> winapi::HCERTSTORE {
        self.0
    }

    fn get_mut(&mut self) -> &mut winapi::HCERTSTORE {
        &mut self.0
    }
}

impl CertStore {
    /// Creates a new in-memory certificate store which certificates and CTLs
    /// can be added to.
    pub fn memory() -> io::Result<Memory> {
        unsafe {
            let store = crypt32::CertOpenStore(winapi::CERT_STORE_PROV_MEMORY as winapi::LPCSTR,
                                               0,
                                               0,
                                               0,
                                               ptr::null_mut());
            if store.is_null() {
                Err(io::Error::last_os_error())
            } else {
                Ok(Memory(CertStore(store)))
            }
        }
    }

    /// Opens up the system root certificate store.
    pub fn system(which: &str) -> io::Result<CertStore> {
        unsafe {
            let data = OsStr::new(which)
                             .encode_wide()
                             .chain(Some(0))
                             .collect::<Vec<_>>();
            let store = crypt32::CertOpenStore(winapi::CERT_STORE_PROV_SYSTEM_W as winapi::LPCSTR,
                                               0,
                                               0,
                                               winapi::CERT_SYSTEM_STORE_CURRENT_USER,
                                               data.as_ptr() as *mut _);
            if store.is_null() {
                Err(io::Error::last_os_error())
            } else {
                Ok(CertStore(store))
            }
        }
    }

    /// Imports a PKCS#12-encoded key/certificate pair, returned as a
    /// `CertStore` instance.
    ///
    /// The password must also be provided to decrypt the encoded data.
    pub fn import_pkcs12(data: &[u8], password: &str) -> io::Result<CertStore> {
        unsafe {
            let mut blob = winapi::CRYPT_INTEGER_BLOB {
                cbData: data.len() as winapi::DWORD,
                pbData: data.as_ptr() as *mut u8,
            };
            let password = OsStr::new(password)
                                 .encode_wide()
                                 .chain(Some(0))
                                 .collect::<Vec<_>>();
            let res = crypt32::PFXImportCertStore(&mut blob,
                                                  password.as_ptr(),
                                                  0);
            if res.is_null() {
                Err(io::Error::last_os_error())
            } else {
                Ok(CertStore(res))
            }
        }
    }

    /// Returns an iterator over the certificates in this certificate store.
    pub fn iter(&mut self) -> CertStoreIter {
        CertStoreIter { store: self, cur: None }
    }
}

/// An iterator over the certificates contained in a `CertStore`, returned by
/// `CertStore::iter`
pub struct CertStoreIter<'a> {
    store: &'a mut CertStore,
    cur: Option<CertContext>,
}

impl<'a> Iterator for CertStoreIter<'a> {
    type Item = CertContext;

    fn next(&mut self) -> Option<CertContext> {
        unsafe {
            let cur = self.cur.as_ref().map(|p| p.as_inner());
            let cur = cur.unwrap_or(ptr::null_mut());
            let next = crypt32::CertEnumCertificatesInStore(self.store.0, cur);

            if next.is_null() {
                self.cur = None;
                None
            } else {
                let next = CertContext::from_inner(next);
                self.cur = Some(next.clone());
                Some(next)
            }
        }
    }
}

/// An in-memory store of certificates and CTLs, created by `CertStore::memory`
/// and can be converted into a `CertStore`.
#[derive(Clone)]
pub struct Memory(CertStore);

impl Memory {
    /// Adds a new certificate to this memory store.
    ///
    /// For example the bytes could be a DER-encoded certificate.
    pub fn add_encoded_certificate(&mut self, cert: &[u8]) -> io::Result<CertContext> {
        unsafe {
            let mut cert_context = ptr::null();

            let res = crypt32::CertAddEncodedCertificateToStore((self.0).0,
                                                                winapi::X509_ASN_ENCODING |
                                                                winapi::PKCS_7_ASN_ENCODING,
                                                                cert.as_ptr() as *const _,
                                                                cert.len() as winapi::DWORD,
                                                                winapi::CERT_STORE_ADD_ALWAYS,
                                                                &mut cert_context);
            if res == winapi::TRUE {
                Ok(CertContext::from_inner(cert_context))
            } else {
                Err(io::Error::last_os_error())
            }
        }
    }

    /// Adds a new CTL to this memory store, in its encoded form.
    ///
    /// This can be created through the `ctl_context::Builder` type.
    pub fn add_encoded_ctl(&mut self, ctl: &[u8]) -> io::Result<CtlContext> {
        unsafe {
            let mut ctl_context = ptr::null();

            let res = crypt32::CertAddEncodedCTLToStore((self.0).0,
                                                        winapi::X509_ASN_ENCODING |
                                                        winapi::PKCS_7_ASN_ENCODING,
                                                        ctl.as_ptr() as *const _,
                                                        ctl.len() as winapi::DWORD,
                                                        winapi::CERT_STORE_ADD_ALWAYS,
                                                        &mut ctl_context);
            if res == winapi::TRUE {
                Ok(CtlContext::from_inner(ctl_context))
            } else {
                Err(io::Error::last_os_error())
            }
        }
    }

    /// Consumes this memory store, returning the underlying `CertStore`.
    pub fn into_store(self) -> CertStore {
        self.0
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn load() {
        let cert = include_bytes!("../test/localhost.der");
        let mut store = CertStore::memory().unwrap();
        store.add_encoded_certificate(cert).unwrap();
    }
}
