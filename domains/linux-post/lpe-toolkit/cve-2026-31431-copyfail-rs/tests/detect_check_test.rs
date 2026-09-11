use copyfail_rs::detect::check::{run_check_with_sources, CheckSources, ConfigState, Verdict};
use std::ffi::CString;
use std::fs;
use std::path::{Path, PathBuf};

fn tmp(name: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("target");
    p.push("test-detect-check");
    p.push(name);
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).unwrap();
    p
}

fn cs(p: &Path) -> CString {
    CString::new(p.as_os_str().as_encoded_bytes()).unwrap()
}

#[allow(dead_code)]
struct Fixture {
    proc_modules: PathBuf,
    proc_crypto: PathBuf,
    boot_config: PathBuf,
    modprobe_d: PathBuf,
    osrelease: PathBuf,
    proc_modules_c: CString,
    proc_crypto_c: CString,
    boot_config_c: CString,
    modprobe_d_c: CString,
    osrelease_c: CString,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let dir = tmp(name);
        let proc_modules = dir.join("modules");
        let proc_crypto = dir.join("crypto");
        let boot_config = dir.join("config");
        let modprobe_d = dir.join("modprobe.d");
        let osrelease = dir.join("osrelease");
        fs::create_dir_all(&modprobe_d).unwrap();
        fs::write(&osrelease, b"6.17.0-22-generic\n").unwrap();
        let proc_modules_c = cs(&proc_modules);
        let proc_crypto_c = cs(&proc_crypto);
        let boot_config_c = cs(&boot_config);
        let modprobe_d_c = cs(&modprobe_d);
        let osrelease_c = cs(&osrelease);
        Fixture {
            proc_modules,
            proc_crypto,
            boot_config,
            modprobe_d,
            osrelease,
            proc_modules_c,
            proc_crypto_c,
            boot_config_c,
            modprobe_d_c,
            osrelease_c,
        }
    }

    fn sources(&self) -> CheckSources<'_> {
        CheckSources {
            proc_modules: self.proc_modules_c.as_c_str(),
            proc_crypto: self.proc_crypto_c.as_c_str(),
            boot_config: self.boot_config_c.as_c_str(),
            modprobe_d_dir: self.modprobe_d_c.as_c_str(),
            osrelease: self.osrelease_c.as_c_str(),
        }
    }
}

#[test]
fn vulnerable_module_loaded_no_blacklist() {
    let f = Fixture::new("vuln_loaded");
    fs::write(
        &f.proc_modules,
        b"algif_aead 16384 0 - Live 0x0000000000000000\nfoo 4096 0 - Live 0x0\n",
    )
    .unwrap();
    fs::write(
        &f.proc_crypto,
        b"name : authencesn(hmac(sha256),cbc(aes))\n",
    )
    .unwrap();
    fs::write(&f.boot_config, b"# config\nCONFIG_CRYPTO_USER_API_AEAD=m\n").unwrap();

    let r = run_check_with_sources(&f.sources()).unwrap();
    assert!(r.algif_aead_loaded);
    assert!(r.authencesn_template);
    assert_eq!(r.config_aead, ConfigState::Module);
    assert!(!r.mitigation_present);
    assert_eq!(r.verdict, Verdict::Vulnerable);
    assert!(!r.config_y_warning);
    assert_eq!(r.kernel_release.as_str(), "6.17.0-22-generic");
}

#[test]
fn vulnerable_builtin_with_blacklist_still_vulnerable() {
    // R3 critical: =y kernel ignores modprobe blacklist
    let f = Fixture::new("vuln_builtin");
    fs::write(&f.proc_modules, b"foo 4096 0 - Live 0x0\n").unwrap();
    fs::write(
        &f.proc_crypto,
        b"name : authencesn(hmac(sha256),cbc(aes))\n",
    )
    .unwrap();
    fs::write(&f.boot_config, b"CONFIG_CRYPTO_USER_API_AEAD=y\n").unwrap();
    fs::write(
        f.modprobe_d.join("disable-algif.conf"),
        b"install algif_aead /bin/false\n",
    )
    .unwrap();

    let r = run_check_with_sources(&f.sources()).unwrap();
    assert_eq!(r.config_aead, ConfigState::Builtin);
    assert!(r.config_y_warning, "must warn that =y bypasses modprobe");
    assert_eq!(r.verdict, Verdict::Vulnerable);
}

#[test]
fn mitigated_module_blacklisted_install_directive() {
    let f = Fixture::new("mit_install");
    fs::write(&f.proc_modules, b"foo 4096 0 - Live 0x0\n").unwrap();
    fs::write(&f.proc_crypto, b"").unwrap();
    fs::write(&f.boot_config, b"CONFIG_CRYPTO_USER_API_AEAD=m\n").unwrap();
    fs::write(
        f.modprobe_d.join("disable-algif.conf"),
        b"install algif_aead /bin/false\n",
    )
    .unwrap();

    let r = run_check_with_sources(&f.sources()).unwrap();
    assert!(!r.algif_aead_loaded);
    assert_eq!(r.config_aead, ConfigState::Module);
    assert!(r.mitigation_present);
    assert_eq!(r.verdict, Verdict::Mitigated);
}

#[test]
fn mitigated_module_blacklisted_blacklist_directive() {
    let f = Fixture::new("mit_blacklist");
    fs::write(&f.proc_modules, b"").unwrap();
    fs::write(&f.proc_crypto, b"").unwrap();
    fs::write(&f.boot_config, b"CONFIG_CRYPTO_USER_API_AEAD=m\n").unwrap();
    fs::write(
        f.modprobe_d.join("blacklist-crypto.conf"),
        b"# comments\nblacklist algif_aead\n",
    )
    .unwrap();

    let r = run_check_with_sources(&f.sources()).unwrap();
    assert!(r.mitigation_present);
    assert_eq!(r.verdict, Verdict::Mitigated);
}

#[test]
fn vulnerable_no_blacklist_module_unloaded_will_autoload() {
    let f = Fixture::new("vuln_unloaded");
    fs::write(&f.proc_modules, b"foo 4096 0 - Live 0x0\n").unwrap();
    fs::write(&f.proc_crypto, b"").unwrap();
    fs::write(&f.boot_config, b"CONFIG_CRYPTO_USER_API_AEAD=m\n").unwrap();

    let r = run_check_with_sources(&f.sources()).unwrap();
    assert!(!r.algif_aead_loaded);
    assert!(!r.mitigation_present);
    assert_eq!(r.verdict, Verdict::Vulnerable);
}

#[test]
fn unknown_when_config_unreadable() {
    // Missing /boot/config-* (locked-down kernel, container without /boot)
    let f = Fixture::new("config_missing");
    fs::write(&f.proc_modules, b"foo 4096 0 - Live 0x0\n").unwrap();
    fs::write(&f.proc_crypto, b"").unwrap();
    // boot_config NOT written

    let r = run_check_with_sources(&f.sources()).unwrap();
    assert_eq!(r.config_aead, ConfigState::Unknown);
    assert_eq!(r.verdict, Verdict::Unknown);
}

#[test]
fn not_exploitable_when_config_n() {
    let f = Fixture::new("config_n");
    fs::write(&f.proc_modules, b"").unwrap();
    fs::write(&f.proc_crypto, b"").unwrap();
    fs::write(
        &f.boot_config,
        b"# CONFIG_CRYPTO_USER_API_AEAD is not set\n",
    )
    .unwrap();

    let r = run_check_with_sources(&f.sources()).unwrap();
    assert_eq!(r.config_aead, ConfigState::NotInKernel);
    assert_eq!(r.verdict, Verdict::NotExploitable);
}
