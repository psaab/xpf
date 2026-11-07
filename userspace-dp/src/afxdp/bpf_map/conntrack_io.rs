//! Address-family dispatch and test-double selection for conntrack-map I/O.
//!
//! Keep the family/fd choice in one place: the test row backend is selected
//! only when the fd chosen for the key's own family is the test sentinel.

use super::*;

#[cfg(test)]
pub(crate) const CONNTRACK_TEST_MAP_FD: c_int = -2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConntrackTarget {
    V4(c_int),
    V6(c_int),
    NoMap { family: u8, fd: c_int },
    CrossFamily,
}

impl ConntrackTarget {
    pub(crate) fn v4_fd(self) -> Option<c_int> {
        match self {
            Self::V4(fd) => Some(fd),
            Self::NoMap { family, fd } if family == libc::AF_INET as u8 => Some(fd),
            Self::V6(_) | Self::NoMap { .. } | Self::CrossFamily => None,
        }
    }

    pub(crate) fn v6_fd(self) -> Option<c_int> {
        match self {
            Self::V6(fd) => Some(fd),
            Self::NoMap { family, fd } if family == libc::AF_INET6 as u8 => Some(fd),
            Self::V4(_) | Self::NoMap { .. } | Self::CrossFamily => None,
        }
    }

    pub(crate) fn is_test_map(self) -> bool {
        match self {
            Self::V4(fd) | Self::V6(fd) => is_conntrack_test_fd(fd),
            Self::NoMap { .. } | Self::CrossFamily => false,
        }
    }
}

/// Select the fd for the key's address family, validating that the IP values
/// agree with the family byte before any caller reaches a map operation.
///
/// A negative fd is `NoMap`, except the test-only sentinel: it becomes a V4 or
/// V6 target only when it occupies that key family's selected slot. This is
/// the single family-sensitive test-double dispatch for every conntrack path.
pub(crate) fn conntrack_target(
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    key: &SessionKey,
) -> ConntrackTarget {
    match (key.addr_family as i32, &key.src_ip, &key.dst_ip) {
        (libc::AF_INET, IpAddr::V4(_), IpAddr::V4(_)) => {
            selected_target(libc::AF_INET as u8, conntrack_v4_fd)
        }
        (libc::AF_INET6, IpAddr::V6(_), IpAddr::V6(_)) => {
            selected_target(libc::AF_INET6 as u8, conntrack_v6_fd)
        }
        _ => ConntrackTarget::CrossFamily,
    }
}

fn selected_target(family: u8, fd: c_int) -> ConntrackTarget {
    if fd >= 0 || is_conntrack_test_fd(fd) {
        if family == libc::AF_INET as u8 {
            ConntrackTarget::V4(fd)
        } else {
            ConntrackTarget::V6(fd)
        }
    } else {
        ConntrackTarget::NoMap { family, fd }
    }
}

/// Whether an fd represents a usable map for any-map-presence checks.
pub(crate) fn conntrack_fd_available(fd: c_int) -> bool {
    fd >= 0 || is_conntrack_test_fd(fd)
}

fn is_conntrack_test_fd(fd: c_int) -> bool {
    #[cfg(test)]
    {
        fd == CONNTRACK_TEST_MAP_FD
    }
    #[cfg(not(test))]
    {
        let _ = fd;
        false
    }
}
