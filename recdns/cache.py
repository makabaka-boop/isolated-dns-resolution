"""正/负缓存。

- 正缓存：按 ``(名称, 类型)`` 保存 RRset，到期时间取自写入时的 TTL；
- NXDOMAIN：只按名称缓存（对该名称的所有类型查询生效）；
- NODATA（无该类型记录）：按 ``(名称, 类型)`` 缓存；
- 负缓存期限取权威区 SOA RR 自身 TTL 与 SOA MINIMUM 字段的较小值。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset


@dataclass
class _PosEntry:
    rrset: dns.rrset.RRset
    expire_at: float


@dataclass
class _NegEntry:
    expire_at: float


def negative_ttl(soa_rrset: Optional[dns.rrset.RRset]) -> Optional[int]:
    """从应答 authority 区的 SOA 计算负缓存 TTL：min(SOA TTL, MINIMUM)。

    没有 SOA 时返回 None（调用方决定默认值）。
    """
    if soa_rrset is None or soa_rrset.rdtype != dns.rdatatype.SOA:
        return None
    minimum = min(rdata.minimum for rdata in soa_rrset)
    return max(0, min(int(soa_rrset.ttl), int(minimum)))


class Cache:
    def __init__(self, default_negative_ttl: int = 30):
        self._positive: dict[tuple[dns.name.Name, int], _PosEntry] = {}
        self._nodata: dict[tuple[dns.name.Name, int], _NegEntry] = {}
        self._nxdomain: dict[dns.name.Name, _NegEntry] = {}
        self._default_negative_ttl = default_negative_ttl

    # -- 写入 ---------------------------------------------------------------

    def put_positive(self, rrset: dns.rrset.RRset, now: float) -> None:
        if not rrset:
            return
        ttl = max(0, int(rrset.ttl))
        self._positive[(rrset.name, rrset.rdtype)] = _PosEntry(rrset, now + ttl)

    def put_nxdomain(self, name: dns.name.Name, ttl: Optional[int], now: float) -> None:
        if ttl is None:
            ttl = self._default_negative_ttl
        self._nxdomain[name] = _NegEntry(now + max(0, int(ttl)))

    def put_nodata(self, name: dns.name.Name, rdtype: int,
                   ttl: Optional[int], now: float) -> None:
        if ttl is None:
            ttl = self._default_negative_ttl
        self._nodata[(name, rdtype)] = _NegEntry(now + max(0, int(ttl)))

    # -- 读取 ---------------------------------------------------------------

    def _alive(self, entry, now: float) -> bool:
        return entry.expire_at > now

    def _get_pos(self, name: dns.name.Name, rdtype: int,
                 now: float) -> Optional[dns.rrset.RRset]:
        entry = self._positive.get((name, rdtype))
        if entry is None:
            return None
        if not self._alive(entry, now):
            del self._positive[(name, rdtype)]
            return None
        return entry.rrset

    def _nx_name(self, name: dns.name.Name, now: float) -> bool:
        entry = self._nxdomain.get(name)
        if entry is None:
            return False
        if not self._alive(entry, now):
            del self._nxdomain[name]
            return False
        return True

    def _nodata_hit(self, name: dns.name.Name, rdtype: int, now: float) -> bool:
        entry = self._nodata.get((name, rdtype))
        if entry is None:
            return False
        if not self._alive(entry, now):
            del self._nodata[(name, rdtype)]
            return False
        return True

    def lookup(self, qname: dns.name.Name, rdtype: int, now: float):
        """返回缓存命中构造的 Answer，未命中返回 None。

        命中形式：
        1. 名称 NXDOMAIN（沿 CNAME 链或直接）；
        2. 正向链最终给出请求类型的 RRset；
        3. 链末端对该类型 NODATA。
        """
        from .resolver import Answer  # 避免模块导入环

        chain: list[dns.rrset.RRset] = []
        seen: set[dns.name.Name] = set()
        cur = qname

        # CNAME 查询不走链逻辑。
        if rdtype != dns.rdatatype.CNAME:
            while True:
                if self._nx_name(cur, now):
                    return Answer.nxdomain(qname, rdtype, cur, chain)
                cname_rr = self._get_pos(cur, dns.rdatatype.CNAME, now)
                if cname_rr is None:
                    break
                chain.append(cname_rr)
                target = cname_rr[0].target
                if target in seen or target == cur:
                    # 缓存里出现环属于数据矛盾，交给上层重新解析时发现。
                    return None
                seen.add(cur)
                cur = target

        if self._nx_name(cur, now):
            return Answer.nxdomain(qname, rdtype, cur, chain)

        terminal = self._get_pos(cur, rdtype, now)
        if terminal is not None:
            chain.append(terminal)
            return Answer.found(qname, rdtype, chain)

        if self._nodata_hit(cur, rdtype, now):
            return Answer.nodata(qname, rdtype, chain)

        # CNAME 链来自缓存，但末端结论不在缓存：按未命中处理，交给网络。
        return None

    # -- 维护 ---------------------------------------------------------------

    def prune(self, now: float) -> None:
        dead = [k for k, e in self._positive.items() if not self._alive(e, now)]
        for k in dead:
            del self._positive[k]
        dead = [k for k, e in self._nodata.items() if not self._alive(e, now)]
        for k in dead:
            del self._nodata[k]
        dead = [k for k, e in self._nxdomain.items() if not self._alive(e, now)]
        for k in dead:
            del self._nxdomain[k]
