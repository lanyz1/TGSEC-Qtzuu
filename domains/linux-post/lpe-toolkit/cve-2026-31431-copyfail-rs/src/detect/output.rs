use crate::detect::baseline::{DiffEntry, DiffKind};
use crate::detect::check::{CheckReport, ConfigState, Verdict};
use crate::detect::scan::{FileVerdict, FsKind, ScanReport};
use core::fmt::Write;
use heapless::String;

pub const OUT_BUF: usize = 8192;

pub fn check_human(r: &CheckReport, out: &mut String<OUT_BUF>) {
    let _ = writeln!(out, "=== copyfail-rs detection: --check ===");
    let _ = writeln!(out, "Kernel:        {}", r.kernel_release.as_str());
    let _ = writeln!(out, "algif_aead:    loaded={}", r.algif_aead_loaded);
    let _ = writeln!(
        out,
        "Template:      authencesn registered={}",
        r.authencesn_template
    );
    let _ = writeln!(out, "Config AEAD:   {}", config_str(r.config_aead));
    let mit = if r.mitigation_present {
        let mut s: String<160> = String::new();
        let _ = s.push_str("present (");
        let _ = s.push_str(r.mitigation_file.as_str());
        let _ = s.push_str(")");
        s
    } else {
        let mut s: String<160> = String::new();
        let _ = s.push_str("none");
        s
    };
    let _ = writeln!(out, "Mitigation:    {}", mit.as_str());
    if r.config_y_warning {
        let _ = writeln!(
            out,
            "WARNING:       CONFIG_CRYPTO_USER_API_AEAD=y — modprobe blacklist BYPASSED"
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "VERDICT:       {}", verdict_str(r.verdict));
    if !r.recommendation.is_empty() {
        let _ = writeln!(out, "RECOMMEND:     {}", r.recommendation);
    }
}

pub fn check_json(r: &CheckReport, out: &mut String<OUT_BUF>) {
    let _ = out.push_str("{");
    let _ = out.push_str("\"kernel\":\"");
    json_escape(&r.kernel_release, out);
    let _ = out.push_str("\",");
    let _ = out.push_str("\"algif_aead_loaded\":");
    let _ = out.push_str(if r.algif_aead_loaded { "true" } else { "false" });
    let _ = out.push_str(",");
    let _ = out.push_str("\"template_registered\":");
    let _ = out.push_str(if r.authencesn_template {
        "true"
    } else {
        "false"
    });
    let _ = out.push_str(",");
    let _ = out.push_str("\"config_aead\":\"");
    let _ = out.push_str(config_str(r.config_aead));
    let _ = out.push_str("\",");
    let _ = out.push_str("\"mitigation\":");
    if r.mitigation_present {
        let _ = out.push_str("{\"file\":\"");
        json_escape(&r.mitigation_file, out);
        let _ = out.push_str("\"}");
    } else {
        let _ = out.push_str("null");
    }
    let _ = out.push_str(",");
    let _ = out.push_str("\"config_y_warning\":");
    let _ = out.push_str(if r.config_y_warning { "true" } else { "false" });
    let _ = out.push_str(",");
    let _ = out.push_str("\"verdict\":\"");
    let _ = out.push_str(verdict_str_lower(r.verdict));
    let _ = out.push_str("\",");
    let _ = out.push_str("\"recommendation\":\"");
    json_escape_str(r.recommendation, out);
    let _ = out.push_str("\"}");
    let _ = out.push_str("\n");
}

pub fn scan_human(r: &ScanReport, out: &mut String<OUT_BUF>) {
    let _ = writeln!(out, "=== copyfail-rs detection: --scan ===");
    let _ = writeln!(
        out,
        "Scanned {} paths in {}ms.",
        r.entries.len(),
        r.elapsed_ms
    );
    let _ = writeln!(out);

    let n_clean = r.count(FileVerdict::Clean);
    let n_tamp = r.count(FileVerdict::Tampered);
    let n_skip = r.count(FileVerdict::Skipped);
    let n_err = r.count(FileVerdict::Error);

    let _ = writeln!(out, "CLEAN ({}):", n_clean);
    for e in r.entries.iter().filter(|e| e.verdict == FileVerdict::Clean) {
        let _ = writeln!(out, "  {} [{}]", e.path.as_str(), fs_str(e.fs));
    }

    if n_tamp > 0 {
        let _ = writeln!(out);
        let _ = writeln!(out, "TAMPERED ({}):", n_tamp);
        for e in r
            .entries
            .iter()
            .filter(|e| e.verdict == FileVerdict::Tampered)
        {
            let _ = writeln!(out, "  {} [{}]", e.path.as_str(), fs_str(e.fs));
            let _ = out.push_str("    cache:  ");
            write_hex(&e.cache_hash, out);
            let _ = out.push_str("\n");
            let _ = out.push_str("    disk:   ");
            write_hex(&e.disk_hash, out);
            let _ = out.push_str("\n");
        }
    }

    if n_skip > 0 {
        let _ = writeln!(out);
        let _ = writeln!(out, "SKIPPED ({}):", n_skip);
        for e in r
            .entries
            .iter()
            .filter(|e| e.verdict == FileVerdict::Skipped)
        {
            let _ = writeln!(out, "  {} — {}", e.path.as_str(), e.note.as_str());
        }
    }

    if n_err > 0 {
        let _ = writeln!(out);
        let _ = writeln!(out, "ERRORS ({}):", n_err);
        for e in r.entries.iter().filter(|e| e.verdict == FileVerdict::Error) {
            let _ = writeln!(out, "  {} — {}", e.path.as_str(), e.note.as_str());
        }
    }

    let _ = writeln!(out);
    if n_tamp > 0 {
        let _ = writeln!(out, "VERDICT:   TAMPERING DETECTED — investigate");
    } else if n_clean == r.entries.len() {
        let _ = writeln!(out, "VERDICT:   CLEAN");
    } else {
        let _ = writeln!(out, "VERDICT:   INCONCLUSIVE (skipped/errors present)");
    }
}

pub fn scan_json(r: &ScanReport, out: &mut String<OUT_BUF>) {
    let _ = out.push_str("{");
    let _ = out.push_str("\"scanned\":");
    let _ = write_usize(out, r.entries.len());
    let _ = out.push_str(",\"elapsed_ms\":");
    let _ = write_usize(out, r.elapsed_ms as usize);
    let _ = out.push_str(",\"entries\":[");
    for (i, e) in r.entries.iter().enumerate() {
        if i > 0 {
            let _ = out.push_str(",");
        }
        let _ = out.push_str("{\"path\":\"");
        json_escape(&e.path, out);
        let _ = out.push_str("\",\"fs\":\"");
        let _ = out.push_str(fs_str(e.fs));
        let _ = out.push_str("\",\"verdict\":\"");
        let _ = out.push_str(verdict_file_str(e.verdict));
        let _ = out.push_str("\",\"cache_hash\":\"");
        write_hex(&e.cache_hash, out);
        let _ = out.push_str("\",\"disk_hash\":\"");
        write_hex(&e.disk_hash, out);
        let _ = out.push_str("\",\"note\":\"");
        json_escape(&e.note, out);
        let _ = out.push_str("\"}");
    }
    let _ = out.push_str("],\"any_tampered\":");
    let _ = out.push_str(if r.any_tampered() { "true" } else { "false" });
    let _ = out.push_str("}\n");
}

pub fn diff_human<const N: usize>(diffs: &heapless::Vec<DiffEntry, N>, out: &mut String<OUT_BUF>) {
    let _ = writeln!(out, "=== copyfail-rs detection: --diff ===");
    if diffs.is_empty() {
        let _ = writeln!(out, "No differences against baseline.");
        return;
    }
    let _ = writeln!(out, "{} entries differ:", diffs.len());
    for d in diffs.iter() {
        let kind = match d.kind {
            DiffKind::DiskTampered => "DISK CHANGED",
            DiffKind::CacheTampered => "CACHE-ONLY (CopyFail signature)",
            DiffKind::BothChanged => "BOTH CHANGED",
            DiffKind::Missing => "MISSING / UNREADABLE",
            DiffKind::SkippedTmpfs => "SKIPPED (tmpfs — no on-disk view)",
        };
        let _ = writeln!(out, "  [{}] {}", kind, d.path.as_str());
        if !matches!(d.kind, DiffKind::Missing | DiffKind::SkippedTmpfs) {
            let _ = out.push_str("    baseline_disk: ");
            write_hex(&d.baseline_disk_hash, out);
            let _ = out.push_str("\n    current_disk:  ");
            write_hex(&d.current_disk_hash, out);
            let _ = out.push_str("\n    current_cache: ");
            write_hex(&d.current_cache_hash, out);
            let _ = out.push_str("\n");
        }
    }
}

fn config_str(c: ConfigState) -> &'static str {
    match c {
        ConfigState::Builtin => "y",
        ConfigState::Module => "m",
        ConfigState::NotInKernel => "n",
        ConfigState::Unknown => "unknown",
    }
}

fn verdict_str(v: Verdict) -> &'static str {
    match v {
        Verdict::Vulnerable => "VULNERABLE",
        Verdict::Mitigated => "MITIGATED",
        Verdict::NotExploitable => "NOT EXPLOITABLE",
        Verdict::Unknown => "UNKNOWN",
    }
}

fn verdict_str_lower(v: Verdict) -> &'static str {
    match v {
        Verdict::Vulnerable => "vulnerable",
        Verdict::Mitigated => "mitigated",
        Verdict::NotExploitable => "not_exploitable",
        Verdict::Unknown => "unknown",
    }
}

fn verdict_file_str(v: FileVerdict) -> &'static str {
    match v {
        FileVerdict::Clean => "clean",
        FileVerdict::Tampered => "tampered",
        FileVerdict::Skipped => "skipped",
        FileVerdict::Error => "error",
    }
}

fn fs_str(f: FsKind) -> &'static str {
    match f {
        FsKind::Ext4 => "ext4",
        FsKind::Xfs => "xfs",
        FsKind::Btrfs => "btrfs",
        FsKind::Overlayfs => "overlayfs",
        FsKind::Tmpfs => "tmpfs",
        FsKind::Other => "other",
    }
}

fn write_hex(bytes: &[u8], out: &mut String<OUT_BUF>) {
    for b in bytes.iter() {
        let _ = out.push(hex_digit_char(b >> 4));
        let _ = out.push(hex_digit_char(b & 0x0F));
    }
}

fn hex_digit_char(n: u8) -> char {
    if n < 10 {
        (b'0' + n) as char
    } else {
        (b'a' + (n - 10)) as char
    }
}

fn write_usize(out: &mut String<OUT_BUF>, n: usize) -> Result<(), core::fmt::Error> {
    write!(out, "{}", n)
}

fn json_escape<const N: usize>(s: &String<N>, out: &mut String<OUT_BUF>) {
    json_escape_str(s.as_str(), out);
}

fn json_escape_str(s: &str, out: &mut String<OUT_BUF>) {
    for c in s.chars() {
        match c {
            '"' => {
                let _ = out.push_str("\\\"");
            }
            '\\' => {
                let _ = out.push_str("\\\\");
            }
            '\n' => {
                let _ = out.push_str("\\n");
            }
            '\r' => {
                let _ = out.push_str("\\r");
            }
            '\t' => {
                let _ = out.push_str("\\t");
            }
            c if (c as u32) < 0x20 => { /* drop */ }
            c => {
                let _ = out.push(c);
            }
        }
    }
}
