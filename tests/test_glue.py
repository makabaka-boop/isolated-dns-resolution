"""Glue 采信策略：只有属于所委派区域且对应 NS 服务器名的地址可用。"""
import dns.name
import dns.rcode
import dns.rdatatype
import pytest

pytestmark = pytest.mark.asyncio


def _types(answer):
    return [r.rdtype for r in answer.chain]


async def test_in_bailiwick_glue_is_used(env):
    # example.org 的 referral 附加 ns.example.org -> 10.3.3.3，
    # 合法且对应 NS 名，直接使用，不另发 ns.example.org 的 A 查询。
    before = len(env.example.calls)
    answer = await env.resolver.resolve("www.example.org.", "A")
    assert {a.address for a in answer.found_rrset} == {"192.0.2.10"}
    # 没有对 ns.example.org 发起独立的 A 解析（只用了 glue）。
    ns_queries = [
        q for q, t, p in env.org.calls + env.root.calls + env.example.calls
        if q == dns.name.from_text("ns.example.org.")
    ]
    assert not ns_queries


async def test_out_of_bailiwick_glue_ignored_and_reresolved(env):
    # org 区为 biz.org 提供两个 NS：
    #   ns.biz.org.  -> 10.3.3.3（合法 in-bailiwick glue）
    #   a.elsewhere.net. 附加区里伪造为 10.6.6.6（越权，必须忽略）
    # a.elsewhere.net. 的真实地址在 net 区是 10.2.2.10；
    # 解析器必须从根重新解析该名字，而不是联系攻击者 10.6.6.6。
    answer = await env.resolver.resolve("www.biz.org.", "A")
    assert answer.rcode == dns.rcode.NOERROR
    assert {a.address for a in answer.found_rrset} == {"192.0.2.20"}

    # 攻击者节点从未被联系。
    assert env.attacker.calls == []

    # 越权 NS 名确实经历了独立的从根解析：net 区被访问，
    # 最终取到 elsewhere.net 权威数据中的真实地址 10.7.7.7（biz 节点）。
    net_names = {q for q, _t, _p in env.netns.calls}
    assert dns.name.from_text("a.elsewhere.net.") in net_names
    assert any(
        q == dns.name.from_text("www.biz.org.")
        for q, _t, _p in env.biz.calls
    )


async def test_attacker_never_reachable_directly(env):
    # 根提示之外的地址不可能被传输层访问：用一个把委派指向
    # 10.6.6.6 的“同区但不是 NS”的伪造 additional 验证。
    # org 区 referral for example.org 仅给 ns.example.org glue；
    # 即使攻击者自称 example.org，解析器只能拿到 10.3.3.3。
    answer = await env.resolver.resolve("www.example.org.", "A")
    assert {a.address for a in answer.found_rrset} != {"203.0.113.66"}
    assert env.attacker.calls == []


async def test_glue_name_must_match_ns_target(env):
    # additional 中即使有“属于所委派区域”的 A，只要其属主名不是
    # NS RRset 中的服务器名，就不能当作 glue 使用。
    from recdns.fake import rr, ns_rr, soa_rr, Zone

    net = env.net
    example_node = net.nodes["10.3.3.3"]
    import dns.name
    parent = next(
        z for z in example_node.zones
        if z.name == dns.name.from_text("example.org.")
    )

    # evil 区：权威 10.3.3.3，但父区故意不给 ns.evil 的 A，
    # 只在附加区放一个同区诱饵 decoy.evil -> 10.6.6.6（攻击者）。
    parent.add(ns_rr("evil.example.org.", "ns.evil.example.org."))
    parent.add(rr("decoy.evil.example.org.", "A", "10.6.6.6"))

    evil_zone = Zone.build("evil.example.org.", [
        soa_rr("evil.example.org.", minimum=30,
               nsname="ns.evil.example.org."),
        ns_rr("evil.example.org.", "ns.evil.example.org."),
        rr("ns.evil.example.org.", "A", "10.3.3.3"),
        rr("www.evil.example.org.", "A", "192.0.2.77"),
    ])
    example_node.zones.append(evil_zone)

    answer = await env.resolver.resolve("www.evil.example.org.", "A")
    assert answer.rcode == dns.rcode.NOERROR
    assert {a.address for a in answer.found_rrset} == {"192.0.2.77"}
    # 诱饵地址（攻击者）从未被使用。
    assert env.attacker.calls == []
