//! #9506 S5: dedicated bounded data-plane socket servers.
//!
//! These listeners are intentionally independent of the JSON control socket.
//! They call the in-process `ReinjectCore`/`SlowPathReinjector` API and never
//! acquire `ServerState` or its snapshot-wide mutex.

use crate::slowpath::SlowPathReinjector;
use crate::slowpath_reinject_9506::{
    decode_announce, decode_cancel, decode_submit_batch, encode_admit, encode_complete, encode_message,
    read_message, AdmitDecision, ReinjectCore, MSG_ADMIT, MSG_ANNOUNCE, MSG_CANCEL, MSG_COMPLETE,
    MSG_SUBMIT_BATCH, ADMIT_SHUTDOWN, SUBMIT_FLAG_DRY_RUN,
};
use arc_swap::ArcSwapOption;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub(crate) fn derive_reinject_submit_path(control_socket: &str) -> String {
    derive_path(control_socket, "reinject-submit.sock")
}

pub(crate) fn derive_reinject_complete_path(control_socket: &str) -> String {
    derive_path(control_socket, "reinject-complete.sock")
}

fn derive_path(control_socket: &str, leaf: &str) -> String {
    match control_socket.rsplit_once('/') {
        Some((dir, _)) => format!("{dir}/{leaf}"),
        None => leaf.to_string(),
    }
}

/// Stateful binary framing for a persistent submit socket. A read timeout may
/// happen after only part of a header/body was consumed; retaining those bytes
/// is required before retrying the next read.
struct FrameReader {
    bytes: Vec<u8>,
    expected_body: Option<usize>,
}

enum FrameRead {
    Ready(u8, Vec<u8>),
    Idle,
    Closed,
}

impl FrameReader {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            expected_body: None,
        }
    }

    fn next<R: Read>(&mut self, reader: &mut R) -> Result<FrameRead, crate::slowpath_reinject_9506::CodecError> {
        let mut chunk = [0u8; 8192];
        loop {
            if self.expected_body.is_none() && self.bytes.len() >= 4 {
                let len = u32::from_be_bytes([
                    self.bytes[0],
                    self.bytes[1],
                    self.bytes[2],
                    self.bytes[3],
                ]) as usize;
                self.bytes.drain(..4);
                if len == 0 {
                    return Err(crate::slowpath_reinject_9506::CodecError::Truncated);
                }
                if len > crate::slowpath_reinject_9506::REINJECT_MAX_MSG {
                    return Err(crate::slowpath_reinject_9506::CodecError::TooLarge);
                }
                self.expected_body = Some(len);
            }
            if let Some(len) = self.expected_body {
                if self.bytes.len() >= len {
                    let body: Vec<u8> = self.bytes.drain(..len).collect();
                    self.expected_body = None;
                    return Ok(FrameRead::Ready(body[0], body[1..].to_vec()));
                }
            }
            match reader.read(&mut chunk) {
                Ok(0) => {
                    if self.bytes.is_empty() && self.expected_body.is_none() {
                        return Ok(FrameRead::Closed);
                    }
                    return Err(crate::slowpath_reinject_9506::CodecError::Truncated);
                }
                Ok(n) => self.bytes.extend_from_slice(&chunk[..n]),
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Ok(FrameRead::Idle);
                }
                Err(err) => {
                    return Err(crate::slowpath_reinject_9506::CodecError::Io(
                        err.to_string(),
                    ));
                }
            }
        }
    }
}
/// Serve one Go submit connection until EOF or a protocol violation. Every
/// frame receives an ADMIT result; CANCEL is one-way and has no response.
pub(crate) fn serve_submit_conn(
    stream: UnixStream,
    fallback_core: &Arc<ReinjectCore>,
    target: &Arc<ArcSwapOption<SlowPathReinjector>>,
) {
    let running = Arc::new(AtomicBool::new(true));
    let authority_handoff = Arc::new(Mutex::new(()));
    serve_submit_conn_with_running(
        stream,
        fallback_core,
        target,
        &running,
        &authority_handoff,
    );
}

fn serve_submit_conn_with_running(
    mut stream: UnixStream,
    fallback_core: &Arc<ReinjectCore>,
    target: &Arc<ArcSwapOption<SlowPathReinjector>>,
    running: &Arc<AtomicBool>,
    authority_handoff: &Arc<Mutex<()>>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(100)));
    let mut reader = FrameReader::new();
    loop {
        let (message_type, payload) = match reader.next(&mut stream) {
            Ok(FrameRead::Ready(message_type, payload)) => (message_type, payload),
            Ok(FrameRead::Idle) => {
                if !running.load(Ordering::Acquire) {
                    break;
                }
                continue;
            }
            Ok(FrameRead::Closed) | Err(_) => break,
        };
        // Serialize authority selection with target installation. The
        // lifecycle handoff copies state and swaps the ArcSwap under this
        // same mutex, so an ANNOUNCE cannot land in the old/new gap.
        let _handoff_guard = authority_handoff
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // The Go client keeps one connection for the daemon lifetime. Resolve
        // the target for every message so a client that connects during
        // startup (before the first snapshot creates the slow path) does not
        // pin the temporary fallback forever.
        let target_reinjector = target.load_full();
        let core = target_reinjector
            .as_ref()
            .map(|reinjector| reinjector.reinject_core())
            .unwrap_or_else(|| fallback_core.clone());
        match message_type {
            MSG_ANNOUNCE => {
                let announcement = match decode_announce(&payload) {
                    Ok(announcement) => announcement,
                    Err(_) => break,
                };
                core.announce_epochs(
                    &announcement.run_id,
                    announcement.generation,
                    announcement.permit_epoch,
                    announcement.permit_open,
                    &announcement.queue_epochs,
                );
            }
            MSG_SUBMIT_BATCH => {
                let frames = match decode_submit_batch(&payload) {
                    Ok(frames) => frames,
                    Err(_) => break,
                };
                let decisions: Vec<AdmitDecision> = frames
                    .iter()
                    .map(|frame| {
                        if frame.flags & SUBMIT_FLAG_DRY_RUN != 0 {
                            if let Some(reinjector) = target_reinjector.as_ref() {
                                reinjector.validate_dry_run_frame(frame.clone())
                            } else {
                                core.refuse_shutdown(frame)
                            }
                        } else if let Some(reinjector) = target_reinjector.as_ref() {
                            reinjector.submit_adjudicated_frame(frame.clone())
                        } else {
                            core.refuse_shutdown(frame)
                        }
                    })
                    .collect();
                let response = encode_message(MSG_ADMIT, &encode_admit(&decisions));
                if stream.write_all(&response).is_err() {
                    break;
                }
            }
            MSG_CANCEL => {
                let scope = match decode_cancel(&payload) {
                    Ok(scope) => scope,
                    Err(_) => break,
                };
                core.cancel(&scope);
            }
            _ => break,
        }
    }
}

/// Stream terminal completions in per-flow order. The completion table owns
/// the bounded queue; this thread only drains and writes binary frames.
pub(crate) fn serve_complete_conn(
    stream: UnixStream,
    core: &Arc<ReinjectCore>,
    running: &Arc<AtomicBool>,
) {
    serve_complete_conn_with_target(stream, core, None, running);
}

pub(crate) fn serve_complete_conn_with_target(
    mut stream: UnixStream,
    fallback_core: &Arc<ReinjectCore>,
    target: Option<&Arc<ArcSwapOption<SlowPathReinjector>>>,
    running: &Arc<AtomicBool>,
) {
    let _ = stream.set_write_timeout(Some(Duration::from_millis(100)));
    loop {
        let running_now = running.load(Ordering::Acquire);
        let target_reinjector = target.and_then(|slot| slot.load_full());
        let core = target_reinjector
            .as_ref()
            .map(|reinjector| reinjector.reinject_core())
            .unwrap_or_else(|| fallback_core.clone());
        if !running_now && core.live_count() == 0 {
            break;
        }
        let completions = core.peek_ready(crate::slowpath_reinject_9506::SUBMIT_MAX_FRAMES);
        if completions.is_empty() {
            if !running.load(Ordering::Acquire) && core.live_count() == 0 {
                break;
            }
            thread::sleep(Duration::from_millis(1));
            continue;
        }
        let response = encode_message(MSG_COMPLETE, &encode_complete(&completions));
        let ids: Vec<u64> = completions
            .iter()
            .map(|completion| completion.request_id)
            .collect();
        if let Err(_err) = stream.write_all(&response) {
            core.release_ready(&ids);
            break;
        }
        let _ = core.ack_ready(&ids);
    }
}

/// Handles retained by the lifecycle owner. Socket paths are next to the JSON
/// control socket, and each listener is owned by its own short-lived thread.
pub(crate) struct ReinjectSocketServers {
    pub submit_path: String,
    pub complete_path: String,
    pub submit_thread: JoinHandle<()>,
    pub complete_thread: JoinHandle<()>,
}

/// Bind both sockets and spawn accept loops. Binding is fail-closed: a stale
/// non-socket object is never unlinked here; the lifecycle helper performs the
/// same object-type check as the control socket before invoking this function.
pub(crate) fn spawn_reinject_socket_servers(
    control_socket: &str,
    core: Arc<ReinjectCore>,
    target: Arc<ArcSwapOption<SlowPathReinjector>>,
    running: Arc<AtomicBool>,
    authority_handoff: Arc<Mutex<()>>,
) -> Result<ReinjectSocketServers, String> {
    let submit_path = derive_reinject_submit_path(control_socket);
    let complete_path = derive_reinject_complete_path(control_socket);
    let submit_listener = UnixListener::bind(&submit_path)
        .map_err(|e| format!("listen reinject submit {submit_path}: {e}"))?;
    if let Err(err) = super::lifecycle::restrict_socket_mode(&submit_path) {
        drop(submit_listener);
        return Err(err);
    }
    let complete_listener = match UnixListener::bind(&complete_path) {
        Ok(listener) => listener,
        Err(err) => {
            drop(submit_listener);
            return Err(format!("listen reinject complete {complete_path}: {err}"));
        }
    };
    if let Err(err) = super::lifecycle::restrict_socket_mode(&complete_path) {
        drop(submit_listener);
        drop(complete_listener);
        return Err(err);
    }
    submit_listener
        .set_nonblocking(true)
        .map_err(|e| format!("set reinject submit nonblocking: {e}"))?;
    complete_listener
        .set_nonblocking(true)
        .map_err(|e| format!("set reinject complete nonblocking: {e}"))?;

    let submit_running = running.clone();
    let submit_core = core.clone();
    let submit_target = target.clone();
    let submit_handoff = authority_handoff.clone();
    let submit_thread = thread::Builder::new()
        .name("xpf-reinject-submit".to_string())
        .spawn(move || {
            while submit_running.load(Ordering::Acquire) {
                match submit_listener.accept() {
                    Ok((stream, _)) => {
                        if let Err(err) =
                            super::lifecycle::reject_unprivileged_peer("reinject submit", &stream)
                        {
                            eprintln!("xpf-userspace-dp: {err}");
                            continue;
                        }
                        serve_submit_conn_with_running(
                            stream,
                            &submit_core,
                            &submit_target,
                            &submit_running,
                            &submit_handoff,
                        );
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(_) => break,
                }
            }
        })
        .map_err(|e| format!("spawn reinject submit server: {e}"))?;

    let complete_running = running.clone();
    let complete_core = core.clone();
    let complete_thread = thread::Builder::new()
        .name("xpf-reinject-complete".to_string())
        .spawn(move || {
            while complete_running.load(Ordering::Acquire) {
                match complete_listener.accept() {
                    Ok((stream, _)) => {
                        if let Err(err) =
                            super::lifecycle::reject_unprivileged_peer("reinject complete", &stream)
                        {
                            eprintln!("xpf-userspace-dp: {err}");
                            continue;
                        }
                        let run = complete_running.clone();
                        let core = complete_core.clone();
                        let target = target.clone();
                        // One completion client is expected (Go pipeline). Serve
                        // it inline so drain order remains globally serialized.
                        serve_complete_conn_with_target(stream, &core, Some(&target), &run);
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(_) => break,
                }
            }
        })
        .map_err(|e| format!("spawn reinject completion server: {e}"))?;

    Ok(ReinjectSocketServers {
        submit_path,
        complete_path,
        submit_thread,
        complete_thread,
    })
}

#[allow(dead_code)]
fn _socket_parent_exists(control_socket: &str) -> bool {
    Path::new(control_socket).parent().is_some_and(Path::exists)
}

#[cfg(test)]
#[path = "reinject_9506_tests.rs"]
mod tests;
