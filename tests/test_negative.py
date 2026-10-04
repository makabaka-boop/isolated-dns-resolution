"""负缓存：NXDOMAIN 按名称、NODATA 按名称+类型，期限取 min(SOA TTL, MINIMUM)。"""
import asyncio
import dns.name
import dns.rcode
import dns.rdatatype
import pytest

pytestmark = pytest.mark.asyncio


def _calls(node):
    return [(q, t) for q, t, _ in node.calls]


async def test_nxdomain_cached_by_name_for_any_type(env):
    name = dns.name.from_text("missing.neg1.example.org.")
    first = await env.resolver.resolve(name, "A")
    assert first.is_nxdomain
    assert first.nx_name == name

    env.example.calls.clear()
    env.org.calls.clear()
    env.root.calls.clear()
    # 同一名称的其它类型也必须命中负缓存，不再访问上游。
    second = await env.resolver.resolve(name, "NS")
    assert second.is_nxdomain and second.cached
    third = await env.resolver.resolve(name, "SOA")
    assert third.is_nxdomain and third.cached
    assert env.example.calls == []
    assert env.org.calls == []
    assert env.root.calls == []


async def test_nodata_cached_by_name_and_type_only(env):
    # present 名字有 A，无 NS -> 对 NS 是 NODATA。
    name = dns.name.from_text("present.neg1.example.org.")
    ns1 = await env.resolver.resolve(name, "NS")
    assert ns1.is_nodata
    env.example.calls.clear()

    # 同一 (名称, 类型) 命中缓存。
    ns2 = await env.resolver.resolve(name, "NS")
    assert ns2.is_nodata and ns2.cached
    assert env.example.calls == []

    # 不同类型（A）不受 NS 的 NODATA 影响。
    a = await env.resolver.resolve(name, "A")
    assert not a.is_nodata
    assert {x.address for x in a.found_rrset} == {"192.0.2.40"}


async def test_negative_ttl_is_min_of_soa_ttl_and_minimum(env):
    # neg1: SOA TTL=300, MINIMUM=1000 -> 300
    name1 = dns.name.from_text("absent.neg1.example.org.")
    await env.resolver.resolve(name1, "A")
    assert _cache_ttl(env, name1, dns.rdatatype.A) is None  # NXDOMAIN 按名
    assert _nx_ttl(env, name1) == 300

    # neg2: SOA TTL=2000, MINIMUM=50 -> 50（NODATA）
    name2 = dns.name.from_text("present.neg2.example.org.")
    await env.resolver.resolve(name2, "NS")
    assert _nodata_ttl(env, name2, dns.rdatatype.NS) == 50


def _nx_ttl(env, name):
    entry = env.resolver.cache._nxdomain[name]
    return entry.expire_at - env.clock.time()


def _nodata_ttl(env, name, rdtype):
    entry = env.resolver.cache._nodata[(name, rdtype)]
    return entry.expire_at - env.clock.time()


def _cache_ttl(env, name, rdtype):
    return None


async def test_nxdomain_expires_at_boundary(env):
    name = dns.name.from_text("gone.neg1.example.org.")  # 负缓存 300
    await env.resolver.resolve(name, "A")
    env.example.calls.clear()

    await env.clock.advance(299)
    hit = await env.resolver.resolve(name, "A")
    assert hit.is_nxdomain and hit.cached
    assert env.example.calls == []

    await env.clock.advance(1)  # 到达 300：边界上视为过期
    miss = await env.resolver.resolve(name, "A")
    assert not miss.cached
    assert env.example.calls  # 重新访问了权威


async def test_nodata_shorter_boundary_uses_minimum(env):
    name = dns.name.from_text("present.neg2.example.org.")  # 负缓存 50
    await env.resolver.resolve(name, "NS")
    env.example.calls.clear()

    await env.clock.advance(49)
    cached = await env.resolver.resolve(name, "NS")
    assert cached.is_nodata and cached.cached
    assert env.example.calls == []

    await env.clock.advance(1)
    refreshed = await env.resolver.resolve(name, "NS")
    assert not refreshed.cached


async def test_positive_ttl_independent_from_negative(env):
    name = dns.name.from_text("present.neg1.example.org.")
    await env.resolver.resolve(name, "A")  # A TTL=200
    env.example.calls.clear()
    await env.clock.advance(199)
    assert (await env.resolver.resolve(name, "A")).cached
    await env.clock.advance(1)
    assert not (await env.resolver.resolve(name, "A")).cached


async def test_cname_to_nxdomain_caches_name_at_target(env):
    # alias 区加一个指向不存在名字的 CNAME。
    from recdns.fake import rr
    env.alias.zones[0].add(
        rr("broken.alias.org.", "CNAME", "nope.target.org.", ttl=40)
    )
    answer = await env.resolver.resolve("broken.alias.org.", "A")
    assert answer.is_nxdomain
    assert answer.nx_name == dns.name.from_text("nope.target.org.")

    env.root.calls.clear()
    env.org.calls.clear()
    # 直接查询不存在的末端名也命中按名称的 NXDOMAIN 缓存。
    again = await env.resolver.resolve("nope.target.org.", "A")
    assert again.is_nxdomain and again.cached
    assert env.root.calls == []
