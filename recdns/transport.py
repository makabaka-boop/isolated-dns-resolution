"""DNS 传输：UDP 优先，收到 TC=1 的 UDP 应答后用 TCP 重试。

所有传输只允许向显式登记/配置的权威服务器地址发包。
"""
from __future__ import annotations

import asyncio
import struct
from typing import Protocol

import dns.message


class Transport(Protocol):
    async def query(self, server: str, port: int,
                    query: dns.message.Message) -> dns.message.Message:
        """发送一个标准查询并返回应答消息。

        实现负责处理 UDP 截断 -> TCP 重试、超时与连接失败；
        失败时抛出 recdns.errors.UpstreamError。
        """
        ...


class RealTransport:
    """真实网络传输（用于对接隔离的测试权威服务器集群）。

    ``allowed`` 限定可访问的服务器地址，未登记地址的查询直接拒绝，
    确保本服务永远不会把查询发往配置范围之外。
    """

    def __init__(self, *, udp_timeout: float = 2.0,
                 tcp_timeout: float = 3.0,
                 udp_payload: int = 512,
                 allowed: "set[str] | None" = None):
        self._udp_timeout = udp_timeout
        self._tcp_timeout = tcp_timeout
        self._udp_payload = udp_payload
        self._allowed = set(allowed) if allowed is not None else None

    def _check_allowed(self, server: str) -> None:
        from .errors import UpstreamError
        if self._allowed is not None and server not in self._allowed:
            raise UpstreamError(f"refusing to query non-configured server {server}")

    async def query(self, server: str, port: int,
                    query: dns.message.Message) -> dns.message.Message:
        self._check_allowed(server)
        wire = query.to_wire()
        response = await self._udp(server, port, wire)
        if response.flags & dns.flags.TC:
            response = await self._tcp(server, port, wire)
        return response

    async def _udp(self, server: str, port: int, wire: bytes) -> dns.message.Message:
        from .errors import UpstreamError
        loop = asyncio.get_running_loop()
        try:
            fut = loop.create_datagram_endpoint(
                lambda: _UDPClient(loop, wire),
                remote_addr=(server, port),
            )
            transport, proto = await asyncio.wait_for(fut, self._udp_timeout)
        except (OSError, asyncio.TimeoutError) as exc:
            raise UpstreamError(f"UDP setup failed for {server}:{port}: {exc}") from exc
        try:
            data = await asyncio.wait_for(proto.response, self._udp_timeout)
        except asyncio.TimeoutError as exc:
            raise UpstreamError(f"UDP timeout for {server}:{port}") from exc
        except OSError as exc:  # ICMP port/host unreachable 等异步错误
            raise UpstreamError(f"UDP exchange failed for {server}:{port}: {exc}") from exc
        finally:
            transport.abort()
        return _parse(data, server, "UDP")

    async def _tcp(self, server: str, port: int, wire: bytes) -> dns.message.Message:
        from .errors import UpstreamError
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(server, port), self._tcp_timeout
            )
        except (OSError, asyncio.TimeoutError) as exc:
            raise UpstreamError(f"TCP connect failed for {server}:{port}: {exc}") from exc
        try:
            writer.write(struct.pack("!H", len(wire)) + wire)
            await writer.drain()
            length = struct.unpack("!H", await _readexactly(reader, 2))[0]
            data = await _readexactly(reader, length)
        except (OSError, asyncio.IncompleteReadError, asyncio.TimeoutError) as exc:
            raise UpstreamError(f"TCP exchange failed for {server}:{port}: {exc}") from exc
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        return _parse(data, server, "TCP")


async def _readexactly(reader: asyncio.StreamReader, n: int) -> bytes:
    return await reader.readexactly(n)


def _parse(data: bytes, server: str, kind: str) -> "dns.message.Message":
    from .errors import UpstreamError
    try:
        return dns.message.from_wire(data)
    except Exception as exc:  # dnspython 的 wire 解析异常类型较多
        raise UpstreamError(f"malformed {kind} response from {server}: {exc}") from exc


class _UDPClient(asyncio.DatagramProtocol):
    def __init__(self, loop: asyncio.AbstractEventLoop, wire: bytes):
        self._wire = wire
        self.response: "asyncio.Future[bytes]" = loop.create_future()

    def connection_made(self, transport) -> None:
        transport.sendto(self._wire)

    def datagram_received(self, data: bytes, addr) -> None:
        if not self.response.done():
            self.response.set_result(data)

    def error_received(self, exc) -> None:
        if not self.response.done():
            self.response.set_exception(exc)

    def connection_lost(self, exc) -> None:
        if not self.response.done():
            self.response.set_exception(exc or OSError("connection closed"))
