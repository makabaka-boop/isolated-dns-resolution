"""递归解析器核心：逐级跟随委派、CNAME 环检测、正/负缓存与在途共享。"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Iterable, Optional

import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from .cache import Cache, negative_ttl
from .clock import AsyncioClock
from .errors import (
    CNAMELoopError,
    InvalidResponseError,
    ResolutionLimitError,
    UnsupportedQueryError,
    UpstreamError,
)

ALLOWED_RDTYPES = (
    dns.rdatatype.A,
    dns.rdatatype.CNAME,
    dns.rdatatype.NS,
    dns.rdatatype.SOA,
)
MAX_HOPS = 8


@dataclass(frozen=True)
class RootHint:
    address: str
    name: Optional[dns.name.Name] = None
    port: int = 53


@dataclass
class Answer:
    """解析结论。

    rcode: NOERROR / NXDOMAIN；
    chain: 从查询名开始的应答 RRset 序列（CNAME 链 + 末端 RRset）。
    对 CNAME 类型查询，末端就是 CNAME RRset。
    """

    qname: dns.name.Name
    rdtype: int
    rcode: int
    chain: list[dns.rrset.RRset] = field(default_factory=list)
    # NXDOMAIN 时实际不存在的名称（可能是 CNAME 链末端）。
    nx_name: Optional[dns.name.Name] = None
    cached: bool = False

    # -- 构造器 -------------------------------------------------------------

    @classmethod
    def found(cls, qname, rdtype, chain) -> "Answer":
        return cls(qname, rdtype, dns.rcode.NOERROR, list(chain))

    @classmethod
    def nodata(cls, qname, rdtype, chain=()) -> "Answer":
        return cls(qname, rdtype, dns.rcode.NOERROR, list(chain))

    @classmethod
    def nxdomain(cls, qname, rdtype, nx_name, chain=()) -> "Answer":
        return cls(qname, rdtype, dns.rcode.NXDOMAIN, list(chain), nx_name=nx_name)

    # -- 访问器 -------------------------------------------------------------

    @property
    def found_rrset(self) -> Optional[dns.rrset.RRset]:
        for r in reversed(self.chain):
            if r.rdtype == self.rdtype:
                return r
        return None

    @property
    def is_nxdomain(self) -> bool:
        return self.rcode == dns.rcode.NXDOMAIN

    @property
    def is_nodata(self) -> bool:
        return self.rcode == dns.rcode.NOERROR and self.found_rrset is None


class RecursiveResolver:
    """配置根提示的递归解析器。

    transport: 具备 ``async query(server, port, message)`` 的对象；
    所有查询只发往根提示与委派链中出现的服务器地址。
    """

    def __init__(self, root_hints: Iterable[RootHint], transport, *,
                 cache: Optional[Cache] = None, clock=None,
                 max_hops: int = MAX_HOPS):
        self._roots = list(root_hints)
        if not self._roots:
            raise ValueError("at least one root hint is required")
        self._transport = transport
        self.cache = cache or Cache()
        self._clock = clock or AsyncioClock()
        self._max_hops = max_hops
        # (qname, rdtype) -> (共享 Task, 等待者 future 列表)。
        self._inflight: dict[
            tuple[dns.name.Name, int],
            tuple[asyncio.Task, list[asyncio.Future]],
        ] = {}

    # ======================================================================
    # 对外入口
    # ======================================================================

    async def resolve(self, qname: "str | dns.name.Name", rdtype) -> Answer:
        if isinstance(qname, str):
            qname = dns.name.from_text(qname)
        if isinstance(rdtype, str):
            rdtype = dns.rdatatype.from_text(rdtype)
        rdtype = int(rdtype)
        if rdtype not in ALLOWED_RDTYPES:
            raise UnsupportedQueryError(
                f"rdtype {dns.rdatatype.to_text(rdtype)} not served "
                "(allowed: A, CNAME, NS, SOA)"
            )
        return await self._resolve(qname, rdtype, frozenset())

    async def _resolve(self, qname, rdtype, glue_stack) -> Answer:
        now = self._clock.time()
        cached = self.cache.lookup(qname, rdtype, now)
        if cached is not None:
            cached.cached = True
            return cached

        # 处在 glue 解析的直接 await 链上时不能挂 inflight 表：
        # 否则 c 的 glue 是 d、d 的 glue 是 c 时会等待一个永不会产生的
        # 共享结果。直接沿当前链跑一次，并继续透传 glue 栈。
        if glue_stack:
            return await self._run((qname, rdtype), glue_stack)

        return await self._join_or_start((qname, rdtype))

    def _join_or_start(self, key) -> "asyncio.Future[Answer]":
        """共享正在进行的上游请求。

        每个等待者拿到的是自己的 future；共享任务只跑一次（结果写入缓存），
        任何单个等待者取消都只摘除自己，绝不取消共享任务或其他等待者。
        """
        loop = asyncio.get_running_loop()
        existing = self._inflight.get(key)
        if existing is not None:
            _, waiters = existing
            mine: "asyncio.Future[Answer]" = loop.create_future()
            waiters.append(mine)
            mine.add_done_callback(self._make_cancel_detacher(key, mine))
            return mine

        mine = loop.create_future()
        waiters = [mine]
        task = loop.create_task(self._run(key, frozenset()))
        self._inflight[key] = (task, waiters)
        task.add_done_callback(self._make_dispatch(key, waiters, task))
        return mine

    def _make_cancel_detacher(self, key, waiter: asyncio.Future):
        def _detach(_fut) -> None:
            if waiter.cancelled():
                self._detach_waiter(key, waiter)
        return _detach

    def _make_dispatch(self, key, waiters, task):
        def _dispatch(_task: asyncio.Task) -> None:
            self._inflight.pop(key, None)
            if task.cancelled():
                outcome = None
            elif task.exception() is not None:
                outcome = task.exception()
            else:
                outcome = task.result()
            for w in list(waiters):
                if w.done():  # 已取消的等待者跳过
                    continue
                if task.cancelled():
                    w.cancel()
                elif isinstance(outcome, BaseException):
                    w.set_exception(outcome)
                else:
                    w.set_result(outcome)
        return _dispatch

    def _detach_waiter(self, key, waiter: asyncio.Future) -> None:
        entry = self._inflight.get(key)
        if entry is not None and waiter in entry[1]:
            entry[1].remove(waiter)

    # ======================================================================
    # 真正干活的单次解析（每个 key 同时只有一个共享任务）
    # ======================================================================

    async def _run(self, key, glue_stack: "frozenset[dns.name.Name]") -> Answer:
        qname, rdtype = key
        chain: list[dns.rrset.RRset] = []
        cname_seen: set[dns.name.Name] = {qname}
        cur = qname
        servers = list(self._roots)
        glue_chain = set(glue_stack)

        for hops in range(self._max_hops):
            response = await self._query_servers(servers, cur, rdtype)
            kind = self._classify(response, cur, rdtype)

            if kind == "answer":
                terminal = self._absorb_answer(
                    response, cur, rdtype, chain, cname_seen
                )
                if terminal is not None:
                    return Answer.found(qname, rdtype, chain)
                # 只拿到部分 CNAME：回到根重新逐级解析目标名。
                cur = chain[-1][0].target
                cname_seen.add(cur)
                servers = list(self._roots)
                continue

            if kind == "nxdomain":
                self._cache_negative(response, cur, rdtype, nxdomain=True)
                return Answer.nxdomain(qname, rdtype, cur, chain)

            if kind == "nodata":
                self._cache_negative(response, cur, rdtype, nxdomain=False)
                return Answer.nodata(qname, rdtype, chain)

            # referral
            cut, ns_rrset = self._referral(response, cur)
            servers = await self._server_addresses(
                ns_rrset, cut, response, glue_chain
            )
            continue

        raise ResolutionLimitError(
            f"delegation limit ({self._max_hops} hops) exceeded for {qname}"
        )

    # ======================================================================
    # 上游通信与故障轮换
    # ======================================================================

    def _make_query(self, qname: dns.name.Name, rdtype: int) -> dns.message.Message:
        msg = dns.message.make_query(qname, rdtype, dns.rdataclass.IN)
        msg.flags &= ~dns.flags.RD  # 对权威服务器发迭代查询
        return msg

    async def _query_servers(self, servers, qname, rdtype) -> dns.message.Message:
        query = self._make_query(qname, rdtype)
        last_exc: Optional[Exception] = None
        for hint in servers:
            try:
                response = await self._transport.query(hint.address, hint.port, query)
                self._validate_envelope(response, query)
                self._validate_rcode(response, qname)
            except (UpstreamError, InvalidResponseError) as exc:
                last_exc = exc
                continue
            return response
        raise UpstreamError(
            f"no acceptable response for {qname} {dns.rdatatype.to_text(rdtype)}"
            + (f": {last_exc}" if last_exc else "")
        )

    @staticmethod
    def _validate_envelope(response, query) -> None:
        if not response.question:
            raise InvalidResponseError("response has no question section")
        q = query.question[0]
        rq = response.question[0]
        if rq.name != q.name or rq.rdtype != q.rdtype:
            raise InvalidResponseError("response question does not match query")
        if not (response.flags & dns.flags.QR):
            raise InvalidResponseError("response lacks QR bit")
        # 权威服务器不应在应答里要求递归服务；AA 与否由分类逻辑判断。

    @staticmethod
    def _validate_rcode(response, qname) -> None:
        rcode = response.rcode()
        if rcode not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN, dns.rcode.NXRRSET):
            raise UpstreamError(
                f"upstream rcode {dns.rcode.to_text(rcode)} for {qname}"
            )

    # ======================================================================
    # 应答分类与缓存写入
    # ======================================================================

    def _classify(self, response, qname: dns.name.Name, rdtype: int) -> str:
        if response.rcode() == dns.rcode.NXDOMAIN:
            return "nxdomain"

        if response.answer:
            return "answer"

        # 无 answer：要么是 referral（authority 有 NS），要么 NODATA（SOA）。
        for r in response.authority:
            if r.rdtype == dns.rdatatype.NS:
                return "referral"
        return "nodata"

    def _absorb_answer(self, response, qname, rdtype, chain, cname_seen):
        """消费 answer 段：验证属主顺序、检测 CNAME 环、写正缓存。

        返回末端 RRset（链终止于请求类型，或 CNAME 查询命中的 CNAME）；
        若应答只给出了链上一段 CNAME（末端还在别处），返回 None。
        """
        now = self._clock.time()
        expect = qname
        terminal: Optional[dns.rrset.RRset] = None

        for rset in response.answer:
            if rset.name != expect:
                raise InvalidResponseError(
                    f"answer RRset owner {rset.name} does not extend chain at {expect}"
                )
            self.cache.put_positive(rset, now)
            chain.append(rset)

            if rset.rdtype == dns.rdatatype.CNAME:
                target = rset[0].target
                if target in cname_seen:
                    names = [r.name for r in chain] + [target]
                    raise CNAMELoopError(target, names)
                cname_seen.add(target)
                expect = target
                terminal = None  # 还有后续节点，暂不算终止
            else:
                terminal = rset
                # 非 CNAME 末端之后不应再出现 RRset；若出现，下一轮的
                # owner 检查（expect 未变）会以 InvalidResponseError 拒绝。

        if terminal is None and rdtype == dns.rdatatype.CNAME:
            # CNAME 查询本身以链上最后一个 CNAME 为答案。
            term = next(
                (r for r in reversed(chain)
                 if r.rdtype == dns.rdatatype.CNAME),
                None,
            )
            return term
        if terminal is not None and terminal.rdtype != rdtype:
            raise InvalidResponseError(
                f"answer terminates with {dns.rdatatype.to_text(terminal.rdtype)} "
                f"but {dns.rdatatype.to_text(rdtype)} was queried"
            )
        return terminal

    def _cache_negative(self, response, qname, rdtype, *, nxdomain: bool) -> None:
        soa = next(
            (r for r in response.authority if r.rdtype == dns.rdatatype.SOA),
            None,
        )
        ttl = negative_ttl(soa)
        now = self._clock.time()
        if nxdomain:
            self.cache.put_nxdomain(qname, ttl, now)
        else:
            self.cache.put_nodata(qname, rdtype, ttl, now)

    # ======================================================================
    # 委派与 glue 处理
    # ======================================================================

    def _referral(self, response, qname: dns.name.Name):
        ns_rrset = next(
            (r for r in response.authority if r.rdtype == dns.rdatatype.NS),
            None,
        )
        if ns_rrset is None:
            raise InvalidResponseError("non-answer response without delegation NS")
        cut = ns_rrset.name
        if not qname.is_subdomain(cut):
            raise InvalidResponseError(
                f"delegation owner {cut} is not a superdomain of {qname}"
            )
        # qname == cut 时：查询子区 apex（NS/SOA），同样跟随到子区权威。
        # AA 位与 referral 互斥；权威应答走 answer 路径。
        if response.flags & dns.flags.AA:
            raise InvalidResponseError("referral must not be authoritative")
        return cut, ns_rrset

    async def _server_addresses(self, ns_rrset, cut, response, glue_chain):
        """从 referral 推出下一跳服务器地址。

        严格规则：additional 中的 A 只有在
          1) 属主名等于某个 NS 目标名，并且
          2) 该名称位于被委派区域内（cut 的真子域）
        时才作为 glue；越权 glue 与“同区但不是 NS”的地址一律丢弃，
        NS 目标改用从根开始的独立递归解析拿地址。
        """
        additional = {
            (r.name, r.rdtype): r
            for r in response.additional
        }
        hints: list[RootHint] = []
        unresolved: list[dns.name.Name] = []

        for ns_rdata in ns_rrset:
            target = ns_rdata.target
            a_rrset = additional.get((target, dns.rdatatype.A))
            # 属于“所委派区域”：NS 名是 cut 的子域（含 cut apex 自身，
            # 如 ns1.example.org 位于 example.org 区顶点是常见的同区 glue）。
            in_bailiwick = a_rrset is not None and target.is_subdomain(cut)
            if in_bailiwick:
                for a in a_rrset:
                    hints.append(RootHint(address=a.address, name=target))
            else:
                unresolved.append(target)

        for target in unresolved:
            if target in glue_chain:
                raise ResolutionLimitError(
                    f"glue name {target} resolves through itself"
                )
            nested_stack = frozenset(glue_chain | {target})
            answer = await self._resolve(target, dns.rdatatype.A, nested_stack)
            rrset = answer.found_rrset
            if rrset is None:
                raise UpstreamError(f"nameserver name {target} has no A record")
            for a in rrset:
                hints.append(RootHint(address=a.address, name=target))

        if not hints:
            raise UpstreamError(
                f"delegation {cut} supplied no usable nameserver addresses"
            )
        return hints
