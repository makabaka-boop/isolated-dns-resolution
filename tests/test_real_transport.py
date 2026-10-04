"""RealTransport 环回集成：同端口 UDP/TCP，验证真实 socket 上的 TC 回退。

服务器只绑定 127.0.0.1 的临时端口，不访问任何外部地址。
"""
import asyncio
import struct

import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rdata
import dns.rrset
import pytest

from recdns.errors import UpstreamError
from recdns.resolver import RecursiveResolver, RootHint
from recdns.transport import RealTransport


def _build_answer(wire: bytes, *, truncate: bool) -> bytes:
    query = dns.message.from_wire(wire)
    q = query.question[0]
    resp = dns.message.Message()
    resp.id = query.id
    resp.question.append(dns.rrset.RRset(q.name, q.rdclass, q.rdtype))
    if truncate:
        resp.flags = dns.flags.QR | dns.flags.TC
        return resp.to_wire()

    resp.flags = dns.flags.QR | dns.flags.AA
    cname = dns.rrset.RRset(q.name, dns.rdataclass.IN, dns.rdatatype.CNAME)
    cname.ttl = 10
    cname.add(dns.rdata.from_text(
        dns.rdataclass.IN, dns.rdatatype.CNAME, "leaf.test."))
    a_rr = dns.rrset.RRset(dns.name.from_text("leaf.test."),
                           dns.rdataclass.IN, dns.rdatatype.A)
    a_rr.ttl = 10
    a_rr.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A,
                                 "127.0.0.1"))
    resp.answer.extend([cname, a_rr])
    return resp.to_wire()


class _AlwaysTruncateUDP(asyncio.DatagramProtocol):
    def __init__(self):
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.transport.sendto(
            _build_answer(data, truncate=True), addr
        )


async def _tcp_handler(reader, writer):
    try:
        while True:
            header = await reader.readexactly(2)
            length = struct.unpack("!H", header)[0]
            wire = await reader.readexactly(length)
            out = _build_answer(wire, truncate=False)
            writer.write(struct.pack("!H", len(out)) + out)
            await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionError):
        pass
    finally:
        writer.close()


@pytest.mark.asyncio
async def test_real_udp_truncation_falls_back_to_real_tcp():
    loop = asyncio.get_running_loop()
    # 先绑 TCP 拿到空闲端口，再在同端口绑 UDP。
    server = await asyncio.start_server(_tcp_handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    udp_transport, _ = await loop.create_datagram_endpoint(
        _AlwaysTruncateUDP, local_addr=("127.0.0.1", port)
    )
    try:
        transport = RealTransport(
            udp_timeout=2.0, tcp_timeout=2.0, allowed={"127.0.0.1"}
        )
        resolver = RecursiveResolver(
            [RootHint("127.0.0.1", port=port)], transport
        )
        answer = await resolver.resolve("loop.test.", "A")
        assert answer.rcode == dns.rcode.NOERROR
        assert [r.rdtype for r in answer.chain] == [
            dns.rdatatype.CNAME, dns.rdatatype.A
        ]
        assert {a.address for a in answer.found_rrset} == {"127.0.0.1"}
    finally:
        udp_transport.close()
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_real_transport_times_out_to_unreachable_port():
    # 白名单地址但端口无人监听：UDP/TCP 都失败，包装成 UpstreamError。
    transport = RealTransport(udp_timeout=0.5, tcp_timeout=0.5,
                              allowed={"127.0.0.1"})
    query = dns.message.make_query("x.test.", "A")
    query.flags &= ~dns.flags.RD
    # 找一个几乎肯定空闲的高端口。
    with pytest.raises(UpstreamError):
        await transport.query("127.0.0.1", 59999, query)
