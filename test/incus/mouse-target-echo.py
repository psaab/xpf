#!/usr/bin/env python3
"""#8259: multi-port TCP echo for the mouse-latency probe.

One asyncio server per mouse port. The probe measures round-trip time on a
persistent connection, so the ONLY thing this must not do is add latency of its
own: no logging per message, no per-connection allocation beyond the reader.
Use one asyncio process for TCP echo and the sequence-numbered HA UDP probe.
The UDP probe replies with the source identity seen on each packet, making a
pool-SNAT reallocation across an RG move observable.
"""
import asyncio
import sys


# #18679: this fixed UDP port is the remote endpoint for the continuous
# sequence-numbered HA probe. It replies with the source identity seen on
# each packet, making pool-SNAT reallocation across an RG move observable.
UDP_PROBE_PORT = 6201
UDP_PROBE_MAGIC = "XPFUDP1"
PORTS = [7] + list(range(6200, 6212))


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


class UDPProbeEcho(asyncio.DatagramProtocol):
    """#18679: echo the client's post-NAT source identity with each sequence."""

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        try:
            magic, run_id, boot_id, sequence = data.decode("ascii").split()
            if magic != UDP_PROBE_MAGIC:
                return
            if (not all(char.isalnum() or char in "_.-" for char in run_id)
                    or len(boot_id) != 32
                    or any(char not in "0123456789abcdef" for char in boot_id)
                    or not sequence.isascii() or not sequence.isdigit()):
                return
            response = (f"{UDP_PROBE_MAGIC} {run_id} {boot_id} {sequence} "
                        f"{addr[0]} {addr[1]}")
            self.transport.sendto(response.encode("ascii"), addr)
        except (UnicodeDecodeError, ValueError):
            return


async def main():
    servers = []
    for port in PORTS:
        try:
            servers.append(await asyncio.start_server(handle, "0.0.0.0", port))
        except OSError as exc:
            print(f"TCP echo port {port}: {exc}", file=sys.stderr, flush=True)
    loop = asyncio.get_running_loop()
    try:
        udp, _ = await loop.create_datagram_endpoint(
            UDPProbeEcho, local_addr=("0.0.0.0", UDP_PROBE_PORT))
    except OSError as exc:
        print(f"UDP probe port {UDP_PROBE_PORT}: {exc}", file=sys.stderr, flush=True)
        raise
    print(f"echo listening on {len(servers)} TCP ports and UDP probe {UDP_PROBE_PORT}", flush=True)
    try:
        await asyncio.gather(*(s.serve_forever() for s in servers))
    finally:
        udp.close()


asyncio.run(main())
