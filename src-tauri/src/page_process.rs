//! Linux, at quit: the page's own processes are ended before the Vault exits.
//!
//! Left to itself, WebKitGTK's page process notices the app has gone and
//! calls `exit`, whose clean-up frees its graphics device while its drawing
//! thread is still letting go of it. On WebKitGTK 2.52 with Mesa that can
//! end in glibc's "corrupted double-linked list" abort a second after a
//! clean quit, and the desktop then shows a crash report dialog for a quit
//! where nothing went wrong. The page has nothing left to do by then (what
//! it stores is written by the network process, which is left alone), so it
//! is ended outright and never reaches that clean-up.

/// The parent's process id in a `/proc/<pid>/stat` line. The program's name
/// sits in brackets and may itself hold spaces and brackets, so the fields
/// are counted from the last closing bracket.
#[cfg(any(target_os = "linux", test))]
fn parent_in_stat(stat: &str) -> Option<u32> {
    let after = &stat[stat.rfind(')')? + 1..];
    after.split_whitespace().nth(1)?.parse().ok()
}

/// End this process's own WebKitGTK page processes. Returns how many.
#[cfg(target_os = "linux")]
pub(crate) fn end_all() -> usize {
    let me = std::process::id();
    let Ok(dir) = std::fs::read_dir("/proc") else { return 0 };
    let mut ended = 0;
    for entry in dir.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) else { continue };
        let base = entry.path();
        let ours = std::fs::read_to_string(base.join("stat")).ok().and_then(|s| parent_in_stat(&s)) == Some(me);
        if !ours {
            continue;
        }
        let is_page = std::fs::read_link(base.join("exe"))
            .ok()
            .and_then(|p| p.file_name().map(|n| n == "WebKitWebProcess"))
            .unwrap_or(false);
        // SAFETY: a signal to a process id read a moment ago, checked to be
        // this process's own child.
        if is_page && unsafe { libc::kill(pid, libc::SIGKILL) } == 0 {
            ended += 1;
        }
    }
    if ended > 0 {
        log::info!("[exit] ended {} page process(es)", ended);
    }
    ended
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn end_all() -> usize {
    0
}

#[cfg(test)]
mod tests {
    use super::parent_in_stat;

    #[test]
    fn the_parent_is_read_past_a_name_with_spaces_and_brackets() {
        assert_eq!(parent_in_stat("777844 (WebKitWebProcess) S 777651 777651 4099 0 -1"), Some(777651));
        assert_eq!(parent_in_stat("12 (a (odd) name) R 7 12 12 0 -1"), Some(7));
        assert_eq!(parent_in_stat("12 (short) S"), None);
        assert_eq!(parent_in_stat("no brackets here"), None);
    }
}
