//! File integrity analyzer for Sign It.
//!
//! Checks files for hidden content (steganography) before signing.
//! All techniques are well-known academic methods, implemented clean-room.
//!
//! Returns an IntegrityReport matching the signing DNA entry type.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

// ── Types (mirror the signing DNA's IntegrityReport) ────────────────

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct IntegrityReport {
    pub checks_performed: Vec<CheckType>,
    pub issues_found: Vec<IntegrityIssue>,
    pub checked_at: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum CheckType {
    PostEofData,
    LsbAnalysis,
    UnicodeSteg,
    MetadataInspection,
    EntropyAnalysis,
    AppendedFileDetection,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct IntegrityIssue {
    pub check_type: CheckType,
    pub severity: Severity,
    pub description: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

// ── File type detection ─────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FileType {
    Png,
    Jpeg,
    Bmp,
    Tiff,
    Gif,
    Pdf,
    Zip,
    Text,
    Unknown,
}

fn detect_file_type(data: &[u8]) -> FileType {
    if data.len() < 4 {
        return FileType::Unknown;
    }
    if data.starts_with(&[0x89, 0x50, 0x4E, 0x47]) {
        FileType::Png
    } else if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        FileType::Jpeg
    } else if data.starts_with(b"BM") {
        FileType::Bmp
    } else if data.starts_with(&[0x49, 0x49, 0x2A, 0x00])
        || data.starts_with(&[0x4D, 0x4D, 0x00, 0x2A])
    {
        FileType::Tiff
    } else if data.starts_with(b"GIF8") {
        FileType::Gif
    } else if data.starts_with(b"%PDF") {
        FileType::Pdf
    } else if data.starts_with(b"PK\x03\x04") {
        FileType::Zip
    } else if is_likely_text(data) {
        FileType::Text
    } else {
        FileType::Unknown
    }
}

fn is_likely_text(data: &[u8]) -> bool {
    let sample = &data[..data.len().min(4096)];
    let printable = sample
        .iter()
        .filter(|&&b| b >= 0x20 || b == b'\n' || b == b'\r' || b == b'\t')
        .count();
    printable as f64 / sample.len() as f64 > 0.85
}

// ── Public API ──────────────────────────────────────────────────────

/// Hash a file using SHA-256. Returns hex-encoded hash.
pub fn hash_file(path: &Path) -> Result<String, String> {
    let mut file =
        std::fs::File::open(path).map_err(|e| format!("Failed to open file: {}", e))?;

    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536]; // 64KB chunks
    loop {
        let bytes_read = file
            .read(&mut buffer)
            .map_err(|e| format!("Failed to read file: {}", e))?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let hash = hasher.finalize();
    Ok(hex::encode(hash))
}

/// Analyze a file for hidden content. Returns an IntegrityReport.
/// Rejects files > 500MB.
pub fn analyze_file(path: &Path) -> Result<IntegrityReport, String> {
    let metadata =
        std::fs::metadata(path).map_err(|e| format!("Failed to read file metadata: {}", e))?;

    if metadata.len() > 500 * 1024 * 1024 {
        return Err("File too large for analysis (max 500MB)".to_string());
    }

    let data =
        std::fs::read(path).map_err(|e| format!("Failed to read file: {}", e))?;

    let file_type = detect_file_type(&data);
    let mut checks_performed = Vec::new();
    let mut issues_found = Vec::new();

    // 1. Post-EOF data detection
    checks_performed.push(CheckType::PostEofData);
    issues_found.extend(check_post_eof(&data, file_type));

    // 2. LSB chi-square analysis (images only)
    if matches!(file_type, FileType::Png | FileType::Bmp | FileType::Tiff) {
        checks_performed.push(CheckType::LsbAnalysis);
        issues_found.extend(check_lsb_chi_square(&data));
    }

    // 3. Unicode steganography (text-like files)
    if matches!(file_type, FileType::Text) || is_likely_text(&data) {
        checks_performed.push(CheckType::UnicodeSteg);
        issues_found.extend(check_unicode_steg(&data));
    }

    // 4. Metadata inspection
    checks_performed.push(CheckType::MetadataInspection);
    issues_found.extend(check_metadata(&data, file_type));

    // 5. Entropy analysis
    checks_performed.push(CheckType::EntropyAnalysis);
    issues_found.extend(check_entropy(&data, file_type));

    // 6. Appended file detection
    checks_performed.push(CheckType::AppendedFileDetection);
    issues_found.extend(check_appended_files(&data));

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    Ok(IntegrityReport {
        checks_performed,
        issues_found,
        checked_at: now,
    })
}

// ── Check 1: Post-EOF data ──────────────────────────────────────────

/// Detect data appended after the file's logical end marker.
fn check_post_eof(data: &[u8], file_type: FileType) -> Vec<IntegrityIssue> {
    let mut issues = Vec::new();

    match file_type {
        FileType::Png => {
            // PNG ends with IEND chunk: 0x00 0x00 0x00 0x00 IEND CRC(4 bytes)
            // Search for IEND marker
            if let Some(pos) = find_bytes(data, b"IEND") {
                // IEND chunk: 4-byte length (0) + 4-byte type (IEND) + 4-byte CRC = 12 bytes
                // The length field starts 4 bytes before "IEND"
                let end_pos = pos + 4 + 4; // past "IEND" + CRC
                if end_pos < data.len() {
                    let extra = data.len() - end_pos;
                    issues.push(IntegrityIssue {
                        check_type: CheckType::PostEofData,
                        severity: Severity::Warning,
                        description: format!(
                            "{} bytes found after PNG IEND marker",
                            extra
                        ),
                    });
                }
            }
        }
        FileType::Jpeg => {
            // JPEG ends with FFD9 (End of Image)
            if let Some(pos) = rfind_bytes(data, &[0xFF, 0xD9]) {
                let end_pos = pos + 2;
                if end_pos < data.len() {
                    let extra = data.len() - end_pos;
                    issues.push(IntegrityIssue {
                        check_type: CheckType::PostEofData,
                        severity: Severity::Warning,
                        description: format!(
                            "{} bytes found after JPEG EOI marker",
                            extra
                        ),
                    });
                }
            }
        }
        FileType::Pdf => {
            // PDF ends with %%EOF
            if let Some(pos) = rfind_bytes(data, b"%%EOF") {
                let end_pos = pos + 5;
                // Allow a few trailing whitespace bytes
                let trailing = &data[end_pos..];
                let non_ws = trailing.iter().filter(|&&b| b != b'\n' && b != b'\r' && b != b' ').count();
                if non_ws > 0 {
                    issues.push(IntegrityIssue {
                        check_type: CheckType::PostEofData,
                        severity: Severity::Warning,
                        description: format!(
                            "{} non-whitespace bytes found after PDF %%EOF marker",
                            non_ws
                        ),
                    });
                }
            }
        }
        FileType::Zip => {
            // ZIP ends with End of Central Directory record (PK\x05\x06)
            if let Some(pos) = rfind_bytes(data, &[0x50, 0x4B, 0x05, 0x06]) {
                // EOCD is at least 22 bytes. Comment length is at offset 20-21 from EOCD start.
                if pos + 20 < data.len() {
                    let comment_len =
                        u16::from_le_bytes([data[pos + 20], data[pos + 21]]) as usize;
                    let expected_end = pos + 22 + comment_len;
                    if expected_end < data.len() {
                        let extra = data.len() - expected_end;
                        issues.push(IntegrityIssue {
                            check_type: CheckType::PostEofData,
                            severity: Severity::Warning,
                            description: format!(
                                "{} bytes found after ZIP end-of-central-directory",
                                extra
                            ),
                        });
                    }
                }
            }
        }
        _ => {}
    }

    issues
}

// ── Check 2: LSB chi-square analysis ────────────────────────────────

/// Statistical test for LSB steganography in images.
/// Uses chi-square test on pixel value pair distributions.
/// High chi-square with pairs being unusually uniform suggests LSB embedding.
fn check_lsb_chi_square(data: &[u8]) -> Vec<IntegrityIssue> {
    let mut issues = Vec::new();

    let img = match image::load_from_memory(data) {
        Ok(img) => img,
        Err(_) => return issues, // Can't decode image, skip
    };

    let rgb = img.to_rgb8();
    let pixels = rgb.as_raw();

    // Chi-square test on each channel
    for (channel_idx, channel_name) in ["Red", "Green", "Blue"].iter().enumerate() {
        // Extract channel values
        let channel_values: Vec<u8> = pixels
            .iter()
            .skip(channel_idx)
            .step_by(3)
            .copied()
            .collect();

        if channel_values.len() < 1000 {
            continue; // Too few samples
        }

        // Build histogram of value pairs (2k, 2k+1)
        let mut histogram = [0u64; 256];
        for &val in &channel_values {
            histogram[val as usize] += 1;
        }

        // Chi-square test on adjacent pairs: compare count(2k) vs count(2k+1)
        let mut chi_square = 0.0_f64;
        let mut pair_count = 0;

        for k in 0..128 {
            let observed_even = histogram[2 * k] as f64;
            let observed_odd = histogram[2 * k + 1] as f64;
            let expected = (observed_even + observed_odd) / 2.0;

            if expected > 0.0 {
                chi_square += (observed_even - expected).powi(2) / expected;
                chi_square += (observed_odd - expected).powi(2) / expected;
                pair_count += 1;
            }
        }

        if pair_count == 0 {
            continue;
        }

        // Degrees of freedom = pair_count - 1
        // For 128 pairs, df = 127. Chi-square > 160 at p < 0.05 is suspicious.
        // We use a simpler threshold: if chi-square per pair is very low,
        // that means pairs are unusually uniform (sign of LSB embedding).
        let chi_per_pair = chi_square / pair_count as f64;

        // Natural images have varied pair ratios (chi_per_pair typically > 1.0).
        // LSB embedding makes pairs nearly equal (chi_per_pair close to 0).
        if chi_per_pair < 0.3 && channel_values.len() > 10000 {
            issues.push(IntegrityIssue {
                check_type: CheckType::LsbAnalysis,
                severity: Severity::Warning,
                description: format!(
                    "{} channel: pixel value pairs are unusually uniform (chi/pair: {:.2}), may indicate LSB steganography",
                    channel_name, chi_per_pair
                ),
            });
        }
    }

    issues
}

// ── Check 3: Unicode steganography ──────────────────────────────────

/// Detect zero-width characters, homoglyphs, and invisible Unicode.
fn check_unicode_steg(data: &[u8]) -> Vec<IntegrityIssue> {
    let mut issues = Vec::new();

    let text = match std::str::from_utf8(data) {
        Ok(t) => t,
        Err(_) => return issues, // Not valid UTF-8, skip
    };

    // Zero-width characters
    let zero_width_chars: &[(char, &str)] = &[
        ('\u{200B}', "Zero Width Space"),
        ('\u{200C}', "Zero Width Non-Joiner"),
        ('\u{200D}', "Zero Width Joiner"),
        ('\u{2060}', "Word Joiner"),
        ('\u{FEFF}', "Zero Width No-Break Space / BOM"),
        ('\u{180E}', "Mongolian Vowel Separator"),
    ];

    let mut total_zero_width = 0;
    let mut found_types = Vec::new();

    for &(ch, name) in zero_width_chars {
        let count = text.matches(ch).count();
        if count > 0 {
            total_zero_width += count;
            found_types.push(format!("{} ({}x)", name, count));
        }
    }

    // Variation selectors (U+FE00-U+FE0F)
    let variation_count: usize = text
        .chars()
        .filter(|&c| ('\u{FE00}'..='\u{FE0F}').contains(&c))
        .count();
    if variation_count > 3 {
        found_types.push(format!("Variation Selectors ({}x)", variation_count));
        total_zero_width += variation_count;
    }

    if total_zero_width > 3 {
        issues.push(IntegrityIssue {
            check_type: CheckType::UnicodeSteg,
            severity: if total_zero_width > 20 {
                Severity::Critical
            } else {
                Severity::Warning
            },
            description: format!(
                "{} invisible Unicode characters found: {}",
                total_zero_width,
                found_types.join(", ")
            ),
        });
    }

    // Cyrillic homoglyphs (characters that look like Latin but are Cyrillic)
    let cyrillic_lookalikes: &[(char, char)] = &[
        ('\u{0430}', 'a'), // а → a
        ('\u{0435}', 'e'), // е → e
        ('\u{043E}', 'o'), // о → o
        ('\u{0440}', 'p'), // р → p
        ('\u{0441}', 'c'), // с → c
        ('\u{0445}', 'x'), // х → x
        ('\u{0443}', 'y'), // у → y
        ('\u{041A}', 'K'), // К → K
        ('\u{041C}', 'M'), // М → M
        ('\u{0422}', 'T'), // Т → T
        ('\u{0410}', 'A'), // А → A
        ('\u{0412}', 'B'), // В → B
        ('\u{0415}', 'E'), // Е → E
        ('\u{041D}', 'H'), // Н → H
        ('\u{041E}', 'O'), // О → O
        ('\u{0420}', 'P'), // Р → P
        ('\u{0421}', 'C'), // С → C
    ];

    let mut homoglyph_count = 0;
    for &(cyrillic, _latin) in cyrillic_lookalikes {
        homoglyph_count += text.matches(cyrillic).count();
    }

    if homoglyph_count > 3 {
        issues.push(IntegrityIssue {
            check_type: CheckType::UnicodeSteg,
            severity: Severity::Warning,
            description: format!(
                "{} Cyrillic homoglyph characters found (look like Latin but are Cyrillic — may be used for steganography)",
                homoglyph_count
            ),
        });
    }

    issues
}

// ── Check 4: Metadata inspection ────────────────────────────────────

/// Check for suspicious metadata: PNG text chunks, JPEG comments, PDF JavaScript.
fn check_metadata(data: &[u8], file_type: FileType) -> Vec<IntegrityIssue> {
    let mut issues = Vec::new();

    match file_type {
        FileType::Png => {
            // Look for tEXt, zTXt, iTXt chunks
            let text_chunks = [b"tEXt", b"zTXt", b"iTXt"];
            for chunk_type in &text_chunks {
                let count = count_occurrences(data, *chunk_type);
                if count > 0 {
                    // tEXt is normal for metadata (e.g., "Software: Adobe Photoshop")
                    // Report as Info unless there are many
                    let severity = if count > 5 {
                        Severity::Warning
                    } else {
                        Severity::Info
                    };
                    issues.push(IntegrityIssue {
                        check_type: CheckType::MetadataInspection,
                        severity,
                        description: format!(
                            "{} PNG {} chunk(s) found",
                            count,
                            std::str::from_utf8(*chunk_type).unwrap_or("???")
                        ),
                    });
                }
            }
        }
        FileType::Jpeg => {
            // JPEG COM (comment) marker: 0xFF 0xFE
            let mut pos = 0;
            let mut comment_count = 0;
            while pos + 1 < data.len() {
                if data[pos] == 0xFF && data[pos + 1] == 0xFE {
                    comment_count += 1;
                }
                pos += 1;
            }
            if comment_count > 0 {
                issues.push(IntegrityIssue {
                    check_type: CheckType::MetadataInspection,
                    severity: if comment_count > 3 {
                        Severity::Warning
                    } else {
                        Severity::Info
                    },
                    description: format!("{} JPEG comment marker(s) found", comment_count),
                });
            }
        }
        FileType::Pdf => {
            // Check for JavaScript in PDF
            let js_markers = [b"/JavaScript" as &[u8], b"/JS "];
            for marker in &js_markers {
                if find_bytes(data, marker).is_some() {
                    issues.push(IntegrityIssue {
                        check_type: CheckType::MetadataInspection,
                        severity: Severity::Critical,
                        description: "PDF contains JavaScript — may execute code when opened"
                            .to_string(),
                    });
                    break;
                }
            }
        }
        _ => {}
    }

    issues
}

// ── Check 5: Entropy analysis ───────────────────────────────────────

/// Detect regions of unusually high entropy in otherwise normal files.
/// High entropy (> 7.5 bits/byte) suggests encrypted or compressed hidden data.
fn check_entropy(data: &[u8], file_type: FileType) -> Vec<IntegrityIssue> {
    let mut issues = Vec::new();

    // Skip for naturally high-entropy files (compressed images, archives)
    if matches!(
        file_type,
        FileType::Jpeg | FileType::Png | FileType::Zip | FileType::Gif
    ) {
        // These formats are already compressed — high entropy is expected.
        // Only check the overall entropy as a sanity check.
        let overall = shannon_entropy(data);
        if overall > 7.99 {
            issues.push(IntegrityIssue {
                check_type: CheckType::EntropyAnalysis,
                severity: Severity::Info,
                description: format!(
                    "Overall entropy is {:.3} bits/byte (near-maximum — expected for compressed format)",
                    overall
                ),
            });
        }
        return issues;
    }

    // For non-compressed files, check sliding windows for high-entropy regions
    let window_size = 4096;
    if data.len() < window_size * 2 {
        // File too small for windowed analysis — just check overall
        let overall = shannon_entropy(data);
        if overall > 7.5 {
            issues.push(IntegrityIssue {
                check_type: CheckType::EntropyAnalysis,
                severity: Severity::Warning,
                description: format!(
                    "File has high entropy ({:.3} bits/byte) — may contain encrypted or compressed hidden data",
                    overall
                ),
            });
        }
        return issues;
    }

    let overall = shannon_entropy(data);
    let mut high_entropy_windows = 0;
    let total_windows = data.len() / window_size;

    for i in 0..total_windows {
        let start = i * window_size;
        let end = start + window_size;
        let window = &data[start..end];
        let entropy = shannon_entropy(window);
        if entropy > 7.5 {
            high_entropy_windows += 1;
        }
    }

    let high_ratio = high_entropy_windows as f64 / total_windows as f64;

    // For text/PDF/BMP, having many high-entropy windows is suspicious
    if high_ratio > 0.2 && overall < 7.0 {
        // Mixed: some high-entropy regions in an otherwise normal file
        issues.push(IntegrityIssue {
            check_type: CheckType::EntropyAnalysis,
            severity: Severity::Warning,
            description: format!(
                "{:.0}% of file has high entropy (> 7.5 bits/byte) while overall is {:.2} — may contain embedded encrypted data",
                high_ratio * 100.0, overall
            ),
        });
    }

    issues
}

/// Calculate Shannon entropy in bits per byte (0.0 to 8.0).
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

// ── Check 6: Appended file detection ────────────────────────────────

/// Scan for known file signatures (magic bytes) at non-zero offsets.
/// Suggests a file has been embedded inside another file.
fn check_appended_files(data: &[u8]) -> Vec<IntegrityIssue> {
    let mut issues = Vec::new();

    let signatures: &[(&[u8], &str)] = &[
        (&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], "PNG"),
        (b"%PDF", "PDF"),
        (&[0xFF, 0xD8, 0xFF], "JPEG"),
        (b"PK\x03\x04", "ZIP"),
        (b"GIF8", "GIF"),
        (&[0x52, 0x61, 0x72, 0x21], "RAR"), // Rar!
        (&[0x1F, 0x8B], "GZIP"),
    ];

    for &(magic, name) in signatures {
        // Skip the first occurrence (that's the file itself)
        let mut search_start = magic.len(); // Start after the header
        if search_start >= data.len() {
            continue;
        }

        if let Some(offset) = find_bytes(&data[search_start..], magic) {
            let absolute_offset = search_start + offset;
            issues.push(IntegrityIssue {
                check_type: CheckType::AppendedFileDetection,
                severity: Severity::Warning,
                description: format!(
                    "Embedded {} file signature found at byte offset {}",
                    name, absolute_offset
                ),
            });
        }
    }

    issues
}

// ── Byte search helpers ─────────────────────────────────────────────

/// Find first occurrence of a byte pattern in data.
fn find_bytes(data: &[u8], pattern: &[u8]) -> Option<usize> {
    if pattern.is_empty() || data.len() < pattern.len() {
        return None;
    }
    data.windows(pattern.len())
        .position(|window| window == pattern)
}

/// Find last occurrence of a byte pattern in data.
fn rfind_bytes(data: &[u8], pattern: &[u8]) -> Option<usize> {
    if pattern.is_empty() || data.len() < pattern.len() {
        return None;
    }
    data.windows(pattern.len())
        .rposition(|window| window == pattern)
}

/// Count occurrences of a byte pattern in data.
fn count_occurrences(data: &[u8], pattern: &[u8]) -> usize {
    if pattern.is_empty() || data.len() < pattern.len() {
        return 0;
    }
    data.windows(pattern.len())
        .filter(|window| *window == pattern)
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shannon_entropy_uniform() {
        // All same byte — entropy should be 0
        let data = vec![0u8; 1000];
        assert!((shannon_entropy(&data) - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_shannon_entropy_random() {
        // Pseudo-random data should have high entropy
        let data: Vec<u8> = (0..=255).cycle().take(2560).collect();
        let entropy = shannon_entropy(&data);
        assert!(entropy > 7.9, "Expected high entropy, got {}", entropy);
    }

    #[test]
    fn test_detect_file_type_png() {
        let data = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00];
        assert_eq!(detect_file_type(&data), FileType::Png);
    }

    #[test]
    fn test_detect_file_type_text() {
        let data = b"Hello, this is a plain text file with normal content.\n";
        assert_eq!(detect_file_type(data), FileType::Text);
    }

    #[test]
    fn test_unicode_steg_clean() {
        let data = b"Normal text with no hidden characters.";
        let issues = check_unicode_steg(data);
        assert!(issues.is_empty(), "Expected no issues for clean text");
    }

    #[test]
    fn test_unicode_steg_zero_width() {
        let text = "Hello\u{200B}\u{200B}\u{200B}\u{200B}\u{200B} World";
        let issues = check_unicode_steg(text.as_bytes());
        assert!(!issues.is_empty(), "Expected issues for zero-width chars");
    }

    #[test]
    fn test_find_bytes() {
        let data = b"Hello IEND World";
        assert_eq!(find_bytes(data, b"IEND"), Some(6));
    }

    #[test]
    fn test_rfind_bytes() {
        let data = b"First %%EOF text %%EOF end";
        assert_eq!(rfind_bytes(data, b"%%EOF"), Some(17));
    }
}
