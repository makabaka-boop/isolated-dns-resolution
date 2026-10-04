"""CNAME 跨区别名链、环检测与链上正缓存。"""
import dns.name
import dns.rcode
import dns.rdatatype
import pytest

from recdns.errors import CNAMELoopError

pytestmark = pytest.mark.asyncio


async def test_cname_chain_across_zones(env):
    answer = await env.resolver.resolve("www.alias.org.", "A")
    assert answer.rcode == dns.rcode.NOERROR
    types = [r.rdtype for r in answer.chain]
    assert types == [dns.rdatatype.CNAME, dns.rdatatype.A]
    assert answer.chain[0][0].target == dns.name.from_text("host.target.org.")
    assert {a.address for a in answer.found_rrset} == {"192.0.2.30"}
    # 每跳都重新从根出发：alias 与 target 是不同委派区。
    assert any(
        q == dns.name.from_text("www.alias.org.")
        for q, _t, _p in env.root.calls
    )
    assert any(
        q == dns.name.from_text("host.target.org.")
        for q, _t, _p in env.root.calls
    )


async def test_cname_chain_served_from_positive_cache(env):
    await env.resolver.resolve("www.alias.org.", "A")
    env.root.calls.clear()
    env.alias.calls.clear()
    env.org.calls.clear()
    answer = await env.resolver.resolve("www.alias.org.", "A")
    assert answer.cached
    assert [r.rdtype for r in answer.chain] == [dns.rdatatype.CNAME,
                                                dns.rdatatype.A]
    assert not env.root.calls and not env.alias.calls

    # 直接查末端名字也命中正缓存。
    direct = await env.resolver.resolve("host.target.org.", "A")
    assert direct.cached
    assert direct.found_rrset is answer.chain[-1] or {
        a.address for a in direct.found_rrset
    } == {"192.0.2.30"}


async def test_cname_self_loop_detected(env):
    with pytest.raises(CNAMELoopError) as exc:
        await env.resolver.resolve("self.alias.org.", "A")
    assert dns.name.from_text("self.alias.org.") == exc.value.name


async def test_cname_two_node_loop_detected(env):
    # loopa -> loopb -> loopa：第二次解析在跟随回 loopa 时发现环。
    with pytest.raises(CNAMELoopError):
        await env.resolver.resolve("loopa.loop.org.", "A")
    with pytest.raises(CNAMELoopError):
        await env.resolver.resolve("loopb.loop.org.", "A")


async def test_cname_type_query_returns_cname(env):
    answer = await env.resolver.resolve("www.alias.org.", "CNAME")
    assert answer.found_rrset.rdtype == dns.rdatatype.CNAME
    assert answer.found_rrset[0].target == dns.name.from_text("host.target.org.")
