//! #9549: ephemeral UDP ports for tests that bind for real.
//!
//! A unit test that binds a FIXED port fails `AddrInUse` whenever a second copy
//! of this crate's suite runs on the same host, and a mutation matrix runs two
//! copies by design. The panic then names a bind, which reads like a product
//! defect. Every test that reaches a real UDP bind takes its port from here.
//!
//! Two shapes, because tests need two different things from the port:
//! - [`hold_ephemeral_udp_port`]: the test needs the port HELD, as a blocker that
//!   makes the code under test fail its bind. Nothing else can take a held port.
//! - [`reserve_ephemeral_udp_port`]: the code under test binds the port itself, so
//!   the test has to release it first. A port is never handed out twice in one
//!   process, so parallel tests in one suite cannot collide with each other.
//!   What remains is another PROCESS taking a released port in the milliseconds
//!   before the code under test binds it. That is far rarer than a fixed port,
//!   which collided with every second copy of the suite, but it is not zero.

use std::collections::HashSet;
use std::net::UdpSocket;
use std::sync::{Mutex, OnceLock};

/// Holds an ephemeral `[::]` UDP port and returns the holders with the port.
///
/// On bindv6only=1 hosts the v6 holder does not cover v4, so a v4 holder on the
/// same port is added when it can be (Codex code-r3 portability nit from #1866).
/// On dual-stack hosts that bind fails `AddrInUse`, because the v6 holder already
/// covers v4, which is fine.
pub(crate) fn hold_ephemeral_udp_port() -> (UdpSocket, Option<UdpSocket>, u16) {
    let holder = UdpSocket::bind(("::", 0)).expect(
        "binding an ephemeral [::]:0 UDP socket failed: this host has no usable IPv6 UDP \
         socket, which is a test-host problem, not a product defect (#9549)",
    );
    let port = holder
        .local_addr()
        .expect("reading back the ephemeral holder's port")
        .port();
    let holder_v4 = UdpSocket::bind(("0.0.0.0", port)).ok();
    (holder, holder_v4, port)
}

/// Reserves an ephemeral UDP port for the code under test to bind, and releases
/// it before returning. Never returns the same port twice in one process. Panics,
/// rather than looping forever, if the kernel keeps returning ports this process
/// has already handed out.
pub(crate) fn reserve_ephemeral_udp_port() -> u16 {
    const ATTEMPTS: usize = 64;
    static HANDED_OUT: OnceLock<Mutex<HashSet<u16>>> = OnceLock::new();
    let handed_out = HANDED_OUT.get_or_init(|| Mutex::new(HashSet::new()));
    for _ in 0..ATTEMPTS {
        let (holder, holder_v4, port) = hold_ephemeral_udp_port();
        let fresh = handed_out.lock().expect("handed-out port set").insert(port);
        drop(holder_v4);
        drop(holder);
        if fresh {
            return port;
        }
    }
    panic!(
        "no fresh ephemeral UDP port after {ATTEMPTS} attempts: the kernel kept returning ports \
         this process already handed out, so the ephemeral range is nearly used up on this test \
         host; this is not a product defect (#9549)"
    );
}

/// Two holders taken at once get distinct ports, which is what lets two copies of
/// the suite run side by side. A bind on a held port fails `AddrInUse`, which is
/// what makes a code-under-test bind attempt observable.
#[test]
fn a_held_port_is_ephemeral_and_actually_held_9549() {
    let (first_holder, _first_v4, first) = hold_ephemeral_udp_port();
    let (_second_holder, _second_v4, second) = hold_ephemeral_udp_port();
    assert_eq!(
        first_holder.local_addr().expect("holder address").port(),
        first,
        "the returned port must be the one the [::] holder holds. The opportunistic v4 holder \
         can mask a mismatch on a dual-stack host, and leave the port unheld for IPv6 on a \
         bindv6only=1 host"
    );
    assert_ne!(
        first, second,
        "two holders taken at once must not share a port: a FIXED port is what made a \
         second copy of the suite fail its pre-bind (#9549)"
    );
    let err = UdpSocket::bind(("::", first))
        .expect_err("control: the returned port must be HELD, or a bind attempt by the code under test would go unseen");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::AddrInUse,
        "control: a bind on a held port must fail AddrInUse, the failure the #1866 cells rely on"
    );
}

/// A reserved port is released, so the code under test can bind it; and 1000
/// reservations are all distinct. Without the handed-out set, the kernel's random
/// choice over the 28232-port ephemeral range repeats a port among 1000 draws with
/// probability 1 - exp(-17.7), so this cell is what binds that set.
#[test]
fn a_reserved_port_is_released_and_never_handed_out_twice_9549() {
    let first = reserve_ephemeral_udp_port();
    let rebind = UdpSocket::bind(("::", first));
    assert!(
        rebind.is_ok(),
        "a reserved port must be RELEASED so the code under test can bind it: {:?}",
        rebind.err()
    );
    drop(rebind);
    let ports: Vec<u16> = (0..1000).map(|_| reserve_ephemeral_udp_port()).collect();
    let distinct: HashSet<u16> = ports.iter().copied().collect();
    assert_eq!(
        distinct.len(),
        ports.len(),
        "a port was handed out twice in one process, so two parallel tests could bind the same one"
    );
    assert!(!distinct.contains(&first), "the first reservation was handed out again");
}
