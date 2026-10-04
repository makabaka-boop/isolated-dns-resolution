"""测试用假权威节点与内存网络。

每个 :class:`FakeAuthority` 模拟一个权威服务器，可承载若干区。
区数据用便于构造的字典提供；委派（NS）记录写在父区，``glue`` 与
应答 additional 段一一对应——包括越权（out-of-bailiwick）和不指向
NS 的伪造条目，以便测试解析器是否严格拒绝。

:class:`FakeNetwork` 按地址登记节点，提供与 RealTransport 相同的
``query(server, port, message)`` 接口；传输策略（UDP 截断 -> TCP）
由解析器经 :meth:`FakeNetwork.query` 复用同一套语义。
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Callable, Optional

import dns.flags
import dns.message
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset


def rr(name: str, rdtype: str, *texts: str, ttl: int = 3600) -> dns.rrset.RRset:
    """构造单个 RRset 的便捷函数。"""
    rdt = dns.rdatatype.from_text(rdtype)
    r = dns.rrset.RRset(dns.name.from_text(name), dns.rdataclass.IN, rdt)
    r.ttl = ttl
    for text in texts:
        r.add(dns.rdata.from_text(dns.rdataclass.IN, rdt, text))
    return r


def soa_rr(zone: str, *, ttl: int = 3600, minimum: int = 60,
           nsname: Optional[str] = None) -> dns.rrset.RRset:
    zone_name = dns.name.from_text(zone)
    if nsname is None:
        nsname = "ns1." if zone_name == dns.name.root else f"ns1.{zone}"
    rname = "hostmaster." if zone_name == dns.name.root else f"hostmaster.{zone}"
    rdata = f"{nsname} {rname} 2024010100 7200 3600 1200 {minimum}"
    return rr(zone, "SOA", rdata, ttl=ttl)


def ns_rr(owner: str, *targets: str, ttl: int = 3600) -> dns.rrset.RRset:
    return rr(owner, "NS", *targets, ttl=ttl)


@dataclass
class Zone:
    """一个权威区。

    records: 精确属主名 -> 类型 -> RRset（A/CNAME/NS/SOA，apex 的 NS/SOA）。
    """
    name: dns.name.Name
    records: dict[dns.name.Name, dict[int, dns.rrset.RRset]] = field(default_factory=dict)

    def add(self, r: dns.rrset.RRset) -> None:
        self.records.setdefault(r.name, {})[r.rdtype] = r

    @classmethod
    def build(cls, name: str, rrsets) -> "Zone":
        z = cls(dns.name.from_text(name))
        for r in rrsets:
            z.add(r)
        return z

    def get(self, name: dns.name.Name, rdtype: int) -> Optional[dns.rrset.RRset]:
        return self.records.get(name, {}).get(rdtype)


class FakeAuthority:
    """模拟权威服务器。

    zones: 本机承载的区列表（按名称长到短排序匹配）。
    delegations 信息直接来自父区 apex 之下的 NS RRset；
    glue 为该 NS 属主的额外附加 RRset（通常是 A），可故意填假。
    """

    def __init__(self, name: str, zones, *,
                 truncate_types: "set[int] | None" = None,
                 hook: "Optional[Callable[[dns.name.Name, int], None]]" = None,
                 gate: "Optional[QueryGate]" = None):
        self.name = name
        self.zones = sorted(zones, key=lambda z: len(z.name.labels), reverse=True)
        # 仅在这些类型上发 UDP 截断（紧随的 TCP 给出完整应答）。None 表示从不截断。
        self.truncate_types = truncate_types
        self.hook = hook or (lambda qname, rdtype: None)
        self.gate = gate
        # 观察用调用日志：(qname, rdtype, protocol)
        self.calls: list[tuple[dns.name.Name, int, str]] = []
        # 已发过 UDP 截断的 (qname, rdtype)，下一次访问按 TCP 完整应答处理。
        self._tc_served: set[tuple[dns.name.Name, int]] = set()

    # -- 内部 ---------------------------------------------------------------

    def _pick_zone(self, qname: dns.name.Name) -> Optional[Zone]:
        best = None
        for z in self.zones:
            if qname.is_subdomain(z.name):
                if best is None or z.name.is_subdomain(best.name):
                    best = z
        return best

    def _delegation(self, zone: Zone, qname: dns.name.Name):
        """在 zone 内找 qname 之下最近的委派点（NS RRset）。

        owner == qname 也算委派：cut 处的 NS RRset 本就是父区数据，
        对 cut apex 的 NS 查询由父区以非权威 referral 形式给出，
        SOA 才需要继续跟随到子区权威。
        """
        best = None
        for owner, types in zone.records.items():
            if owner == zone.name:
                continue  # 本区 apex NS 不是向外委派
            ns_set = types.get(dns.rdatatype.NS)
            if ns_set is not None and qname.is_subdomain(owner):
                if best is None or owner.is_subdomain(best[0]):
                    best = (owner, ns_set)
        return best

    def build_response(self, qname: dns.name.Name, rdtype: int) -> dns.message.Message:
        response = dns.message.Message()
        response.flags = dns.flags.QR | dns.flags.AA
        question = dns.rrset.RRset(qname, dns.rdataclass.IN, rdtype)
        response.question.append(question)

        zone = self._pick_zone(qname)
        if zone is None:
            # REFUSED：未配置该区。
            response.set_rcode(dns.rcode.REFUSED)
            return response

        # apex 的 NS/SOA 是权威数据，必须先于委派处理。
        if qname == zone.name:
            apex_exact = zone.get(qname, rdtype)
            if apex_exact is not None:
                response.answer.append(apex_exact)
                response.set_rcode(dns.rcode.NOERROR)
                return response

        delegation = self._delegation(zone, qname)
        if delegation is not None:
            cut, ns_set = delegation
            # 委派：非权威，answer 空，authority 放 NS。
            response.flags &= ~dns.flags.AA
            response.set_rcode(dns.rcode.NOERROR)
            response.authority.append(ns_set)
            # additional 中的每个 A 都按父区数据原样给出——包括故意伪造的
            # 越权/非 NS 名字的 glue；是否采信由解析器决定。
            # 注意：只从“父区”记录里取，不跨到子区 apex——真实的父区
            # 权威不可能知道子区后来自行配置的地址。
            extra_names = {r.target for r in ns_set}
            extra_names.add(cut)
            for name in extra_names:
                for gt in (dns.rdatatype.A, dns.rdatatype.AAAA):
                    glue = zone.get(name, gt)
                    if glue is not None:
                        response.additional.append(glue)
            return response

        # 非 apex、无委派：CNAME 优先（CNAME 属主不应有其它类型并存）。
        cname = zone.get(qname, dns.rdatatype.CNAME)
        if cname is not None:
            response.answer.append(cname)
            target = cname[0].target
            # 若本机也知道目标记录（同区或承载的别区），附上链上后续数据。
            tz = self._pick_zone(target)
            if tz is not None and self._delegation(tz, target) is None:
                requested = tz.get(target, rdtype)
                if requested is not None:
                    response.answer.append(requested)
                elif rdtype != dns.rdatatype.CNAME:
                    next_cname = tz.get(target, dns.rdatatype.CNAME)
                    if next_cname is not None:
                        response.answer.append(next_cname)
            response.set_rcode(dns.rcode.NOERROR)
            return response

        exact = zone.get(qname, rdtype)
        if exact is not None:
            response.answer.append(exact)
            response.set_rcode(dns.rcode.NOERROR)
            return response

        # 名称存在/不存在的否定应答：authority 放 SOA。
        apex_soa = zone.get(zone.name, dns.rdatatype.SOA)
        if apex_soa is not None:
            response.authority.append(apex_soa)
        name_exists = bool(zone.records.get(qname))
        if name_exists:
            response.set_rcode(dns.rcode.NOERROR)   # NODATA
        else:
            response.set_rcode(dns.rcode.NXDOMAIN)
        return response


class QueryGate:
    """让一次上游查询挂起，直到测试显式放行。

    ``holds(predicate)`` 设定哪些 (qname, rdtype) 需要挂起；被挂起的
    查询阻塞在 :meth:`enter`，:meth:`release_all` 放行，
    :meth:`cancel_one` 从“网络一侧”取消其中一个等待（用于异常路径测试）。
    """

    def __init__(self):
        self._pending: list[tuple[dns.name.Name, int, asyncio.Event,
                                  "asyncio.Future[None]"]] = []
        self._predicate = lambda q, t: False

    def holds(self, predicate) -> "QueryGate":
        self._predicate = predicate
        return self

    async def enter(self, qname: dns.name.Name, rdtype: int):
        if not self._predicate(qname, rdtype):
            return
        event = asyncio.Event()
        loop = asyncio.get_running_loop()
        cancel_fut = loop.create_future()
        self._pending.append((qname, rdtype, event, cancel_fut))
        release = asyncio.ensure_future(event.wait())
        try:
            await asyncio.wait(
                {release, cancel_fut}, return_when=asyncio.FIRST_COMPLETED
            )
        finally:
            release.cancel()
        if cancel_fut.done():
            raise cancel_fut.exception() or asyncio.CancelledError()

    def pending(self) -> list[tuple[dns.name.Name, int]]:
        return [(q, t) for q, t, e, c in self._pending if not e.is_set()]

    def release_all(self) -> int:
        n = 0
        for q, t, e, c in self._pending:
            if not e.is_set():
                e.set()
                n += 1
        return n

    def cancel_one(self, index: int = 0) -> bool:
        live = [(q, t, e, c) for q, t, e, c in self._pending if not e.is_set()]
        if index >= len(live):
            return False
        _, _, _, c = live[index]
        c.set_exception(asyncio.CancelledError())
        return True


class FakeNetwork:
    """按 IPv4 地址登记假权威节点的内存网络。"""

    def __init__(self):
        self.nodes: dict[str, FakeAuthority] = {}

    def add_node(self, address: str, node: FakeAuthority) -> FakeAuthority:
        self.nodes[address] = node
        return node

    def node(self, address: str) -> FakeAuthority:
        return self.nodes[address]

    def _node(self, server: str) -> FakeAuthority:
        from .errors import UpstreamError
        node = self.nodes.get(server)
        if node is None:
            raise UpstreamError(f"no fake authority registered at {server}")
        return node

    async def udp_query(self, server: str,
                        query: dns.message.Message) -> dns.message.Message:
        node = self._node(server)
        q = query.question[0]
        qname, rdtype = q.name, q.rdtype

        if node.gate is not None:
            await node.gate.enter(qname, rdtype)
        node.hook(qname, rdtype)

        if (node.truncate_types is not None
                and rdtype in node.truncate_types
                and (qname, rdtype) not in node._tc_served):
            node._tc_served.add((qname, rdtype))
            node.calls.append((qname, rdtype, "UDP-TC"))
            short = dns.message.Message()
            short.flags = dns.flags.QR | dns.flags.TC
            short.question.append(dns.rrset.RRset(
                qname, dns.rdataclass.IN, rdtype))
            short.set_rcode(dns.rcode.NOERROR)
            return short

        node.calls.append((qname, rdtype, "UDP"))
        await asyncio.sleep(0)  # 让出，模拟异步往返
        return node.build_response(qname, rdtype)

    async def tcp_query(self, server: str,
                        query: dns.message.Message) -> dns.message.Message:
        node = self._node(server)
        q = query.question[0]
        qname, rdtype = q.name, q.rdtype
        if node.gate is not None:
            await node.gate.enter(qname, rdtype)
        node.hook(qname, rdtype)
        node.calls.append((qname, rdtype, "TCP"))
        await asyncio.sleep(0)
        return node.build_response(qname, rdtype)


class FakeTransport:
    """与 RealTransport 语义一致的内存传输：UDP 收到 TC 后用 TCP 重试。

    ``port`` 参数被忽略（假网络按服务器地址索引），保留它只是为了与
    RealTransport 的接口形状一致。
    """

    def __init__(self, network: FakeNetwork):
        self._net = network

    async def query(self, server: str, port: int,
                    query: dns.message.Message) -> dns.message.Message:
        response = await self._net.udp_query(server, query)
        if response.flags & dns.flags.TC:
            response = await self._net.tcp_query(server, query)
        return response
