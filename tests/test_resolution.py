"""端到端功能测试：基本解析、委派跟随、NS/SOA、八跳上限。"""
import asyncio
import dns.name
import dns.rcode
import dns.rdatatype
import pytest

from recdns.errors import (
    ResolutionLimitError,
    UnsupportedQueryError,
)

pytestmark = pytest.mark.asyncio


async def test_basic_a_resolution_follows_delegation(env):
    answer = await env.resolver.resolve("www.example.org.", "A")
    assert answer.rcode == dns.rcode.NOERROR
    r = answer.found_rrset
    assert r is not None
    assert {a.address for a in r} == {"192.0.2.10"}
    # 链路：root -> org -> example，三台机器都被访问。
    root_names = {q for q, _t, _proto in env.root.calls}
    assert dns.name.from_text("www.example.org.") in root_names


async def test_positive_cache_served_without_upstream(env):
    await env.resolver.resolve("www.example.org.", "A")
    env.root.calls.clear()
    env.org.calls.clear()
    env.example.calls.clear()
    answer = await env.resolver.resolve("www.example.org.", "A")
    assert answer.cached is True
    assert not env.root.calls
    assert not env.org.calls
    assert not env.example.calls


async def test_ns_and_soa_at_apex(env):
    soa_ans = await env.resolver.resolve("example.org.", "SOA")
    assert soa_ans.found_rrset.rdtype == dns.rdatatype.SOA
    ns_ans = await env.resolver.resolve("example.org.", "NS")
    assert {r.target.to_text() for r in ns_ans.found_rrset} == {"ns.example.org."}


async def test_unsupported_rdtype_rejected(env):
    with pytest.raises(UnsupportedQueryError):
        await env.resolver.resolve("example.org.", "MX")
    with pytest.raises(UnsupportedQueryError):
        await env.resolver.resolve("example.org.", "AAAA")


async def test_delegation_hop_limit(env):
    # x.i...a.deep.org：root(1) -> org(2) -> deep(3) -> a(4) ... -> i(12)，
    # 第八跳只能走到 e.d.c.b.a.deep.org，之后再委派即超限。
    target = "x." + ".".join("ihgfedcba") + ".deep.org."
    with pytest.raises(ResolutionLimitError):
        await env.resolver.resolve(target, "A")


async def test_eight_hops_exact_boundary(env):
    # 第八跳恰好到达 e.d.c.b.a.deep.org 顶点，其 NS 查询在边界内成功；
    # 再深一级的委派（f....）落到第九跳，无法跟随。
    at_limit = ".".join("edcba") + ".deep.org."
    answer = await env.resolver.resolve(at_limit, "NS")
    assert answer.found_rrset is not None

    beyond = "y." + ".".join("fedcba") + ".deep.org."
    with pytest.raises(ResolutionLimitError):
        await env.resolver.resolve(beyond, "A")
