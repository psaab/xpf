#!/usr/bin/env python3
"""#8259: multi-port TCP echo for the mouse-latency probe.

One asyncio server per mouse port. The probe measures round-trip time on a
persistent connection, so the ONLY thing this must not do is add latency of its
own: no logging per message, no per-connection allocation beyond the reader.
Use one asyncio process for TCP echo and the sequence-numbered HA UDP probe.
The UDP probe replies with the source identity seen on each packet, making a
pool-SNAT reallocation across an RG move observable.

#19022: the UDP reply leaves FROM the address the datagram arrived on. The
socket is bound to the wildcard, so a plain sendto() lets the kernel pick the
interface's primary address. On loss the target carries .201 (primary) and
.202 (alias, IPERF_TARGET4): a probe to .202 was answered from .201, which
matched no firewall session and which the probe's connected socket ignores.
IP_PKTINFO / IPV6_RECVPKTINFO report the local address of each datagram and
the reply carries it back in the same control message. A socket per address
would miss an alias added after start (`up` restarts mouse-addr.service after
this daemon).
"""
import asyncio
import socket
import struct
import sys


# #18679: this fixed UDP port is the remote endpoint for the continuous
# sequence-numbered HA probe. It replies with the source identity seen on
# each packet, making pool-SNAT reallocation across an RG move observable.
UDP_PROBE_PORT = 6201
UDP_PROBE_MAGIC = "XPFUDP1"
PORTS = [7] + list(range(6200, 6212))

# Linux values. The socket module names IP_PKTINFO only from Python 3.13.
IP_PKTINFO = getattr(socket, "IP_PKTINFO", 8)
IPV6_RECVPKTINFO = getattr(socket, "IPV6_RECVPKTINFO", 49)
IPV6_PKTINFO = getattr(socket, "IPV6_PKTINFO", 50)
IN_PKTINFO = struct.Struct("=i4s4s")      # ipi_ifindex, ipi_spec_dst, ipi_addr
IN6_PKTINFO = struct.Struct("=16sI")      # ipi6_addr, ipi6_ifindex
UDP_RECV_BYTES = 4096
UDP_BATCH = 64


async def handle(reader, writer):
    try:
        while True:
            data = await reader.read(4096)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


def udp_probe_response(data, addr):
    """#18679: the reply to one probe datagram, or None to stay silent."""
    try:
        magic, run_id, boot_id, sequence = data.decode("ascii").split()
        if magic != UDP_PROBE_MAGIC:
            return None
        if (not all(char.isalnum() or char in "_.-" for char in run_id)
                or len(boot_id) != 32
                or any(char not in "0123456789abcdef" for char in boot_id)
                or not sequence.isascii() or not sequence.isdigit()):
            return None
        response = (f"{UDP_PROBE_MAGIC} {run_id} {boot_id} {sequence} "
                    f"{addr[0]} {addr[1]}")
        return response.encode("ascii")
    except (UnicodeDecodeError, ValueError):
        return None


class UDPProbeEcho:
    """#18679 echo of the client's post-NAT source identity per sequence.

    #19022: replies from the local address each datagram was received on.
    """

    def __init__(self, family, port):
        sock = socket.socket(family, socket.SOCK_DGRAM)
        try:
            if family == socket.AF_INET6:
                # IPv4 stays on its own socket: a v4-mapped peer would change
                # the identity text the reply carries.
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                sock.setsockopt(socket.IPPROTO_IPV6, IPV6_RECVPKTINFO, 1)
                sock.bind(("::", port))
                self.cmsg_level, self.cmsg_type = socket.IPPROTO_IPV6, IPV6_PKTINFO
                self.cmsg_space = socket.CMSG_SPACE(IN6_PKTINFO.size)
            else:
                sock.setsockopt(socket.IPPROTO_IP, IP_PKTINFO, 1)
                sock.bind(("0.0.0.0", port))
                self.cmsg_level, self.cmsg_type = socket.IPPROTO_IP, IP_PKTINFO
                self.cmsg_space = socket.CMSG_SPACE(IN_PKTINFO.size)
            sock.setblocking(False)
        except OSError:
            sock.close()
            raise
        self.family = family
        self.sock = sock

    def reply_pktinfo(self, ancdata):
        """The send-side PKTINFO naming the datagram's local address."""
        for level, kind, data in ancdata:
            if level != self.cmsg_level or kind != self.cmsg_type:
                continue
            if self.family == socket.AF_INET6:
                if len(data) < IN6_PKTINFO.size:
                    return None
                local, ifindex = IN6_PKTINFO.unpack_from(data)
                if local[0] == 0xFF:
                    # Multicast is never a source: let the kernel choose.
                    local = bytes(16)
                return [(level, kind, IN6_PKTINFO.pack(local, ifindex))]
            if len(data) < IN_PKTINFO.size:
                return None
            _ifindex, spec_dst, _header_dst = IN_PKTINFO.unpack_from(data)
            # ipi_spec_dst is the local address for this datagram (its header
            # destination for unicast). ifindex 0 leaves egress to routing.
            return [(level, kind, IN_PKTINFO.pack(0, spec_dst, bytes(4)))]
        return None

    def on_readable(self):
        for _ in range(UDP_BATCH):
            try:
                data, ancdata, _flags, addr = self.sock.recvmsg(
                    UDP_RECV_BYTES, self.cmsg_space)
            except (BlockingIOError, InterruptedError):
                return
            except OSError:
                return
            response = udp_probe_response(data, addr)
            if response is None:
                continue
            pktinfo = self.reply_pktinfo(ancdata)
            try:
                if pktinfo is None:
                    # No PKTINFO (not expected on Linux): the pre-#19022
                    # wildcard reply is still right on a one-address host.
                    self.sock.sendto(response, addr)
                else:
                    self.sock.sendmsg([response], pktinfo, 0, addr)
            except OSError:
                # UDP: a full send buffer or a vanished address drops this
                # one reply, as the asyncio transport's error path did.
                continue

    def close(self):
        self.sock.close()


async def main():
    servers = []
    for port in PORTS:
        try:
            servers.append(await asyncio.start_server(handle, "0.0.0.0", port))
        except OSError as exc:
            print(f"TCP echo port {port}: {exc}", file=sys.stderr, flush=True)
    loop = asyncio.get_running_loop()
    udp_echoes = []
    try:
        udp_echoes.append(UDPProbeEcho(socket.AF_INET, UDP_PROBE_PORT))
    except OSError as exc:
        print(f"UDP probe port {UDP_PROBE_PORT}: {exc}", file=sys.stderr, flush=True)
        raise
    try:
        udp_echoes.append(UDPProbeEcho(socket.AF_INET6, UDP_PROBE_PORT))
    except OSError as exc:
        # A host without IPv6 still serves the (IPv4-only) HA probe.
        print(f"UDP probe port {UDP_PROBE_PORT} IPv6: {exc}", file=sys.stderr, flush=True)
    for echo in udp_echoes:
        loop.add_reader(echo.sock.fileno(), echo.on_readable)
    print(f"echo listening on {len(servers)} TCP ports and UDP probe {UDP_PROBE_PORT} "
          f"({len(udp_echoes)} address families)", flush=True)
    try:
        await asyncio.gather(*(s.serve_forever() for s in servers))
    finally:
        for echo in udp_echoes:
            loop.remove_reader(echo.sock.fileno())
            echo.close()


asyncio.run(main())
