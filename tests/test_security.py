"""安全边界：只访问配置内权威地址；自引用 glue 被拒；无 SOA 时的默认负缓存。"""
import dns.name
import dns.rcode
import dns.rdatatype
import pytest

from recdns.errors import ResolutionLimitError, UpstreamError
from recdns.resolver import RecursiveResolver, RootHint
from recdns.transport import RealTransport

pytestmark = pytest.mark.asyncio


async def test_real_transport_refuses_non_configured_address():
    # 白名单外的地址在发包前直接拒绝（这里不会真正产生网络流量）。
    t = RealTransport(allowed={"10.0.0.1"})
    import dns.message
    q = dns.message.make_query("example.", "A")
    with pytest.raises(UpstreamError, match="non-configured"):
        await t.query("8.8.8.8", 53, q)


async def test_self_referential_glue_is_detected(env):
    # 父区把 selfns.example.org 委派给 ns.selfns.example.org，
    # 但不给任何地址；而 ns.selfns.example.org 的 A 又只可能由
    # selfns 区自己提供——解析它必须先到达同一台（尚不可达的）权威，
    # 形成自引用 glue 链。解析器必须明确报错，不能无限递归，
    # 也不能向任何非配置地址发包。
    from recdns.fake import rr, ns_rr, FakeTransport
    import dns.name
    net = env.net
    example_node = net.nodes["10.3.3.3"]
    parent = next(
        z for z in example_node.zones
        if z.name == dns.name.from_text("example.org.")
    )
    parent.add(ns_rr("selfns.example.org.", "ns.selfns.example.org."))
    # 父区附加区故意空：没有 ns.selfns 的 A。

    fresh = RecursiveResolver(
        [RootHint("10.0.0.1")], FakeTransport(net), clock=env.clock
    )
    try:
        got = await fresh.resolve("www.selfns.example.org.", "A")
    except ResolutionLimitError:
        assert env.attacker.calls == []
        return
    assert False, f"expected ResolutionLimitError, got rcode={got.rcode}"


async def test_default_negative_ttl_without_soa(env):
    # 造一个返回 NXDOMAIN 但 authority 无 SOA 的区，默认负缓存 30s。
    from recdns.fake import FakeAuthority, Zone
    bare = Zone.build("bare.example.org.", [
        # 只有 apex NS，没有 SOA
        __import__("recdns.fake", fromlist=["ns_rr"]).ns_rr(
            "bare.example.org.", "ns.example.org."),
    ])
    env.net.nodes["10.3.3.3"].zones.append(bare)

    from recdns.cache import Cache
    from recdns.fake import FakeTransport
    fresh = RecursiveResolver(
        [RootHint("10.0.0.1")], FakeTransport(env.net),
        clock=env.clock, cache=Cache(default_negative_ttl=30),
    )
    name = dns.name.from_text("x.bare.example.org.")
    ans = await fresh.resolve(name, "A")
    assert ans.is_nxdomain
    entry = fresh.cache._nxdomain[name]
    assert entry.expire_at - env.clock.time() == 30
