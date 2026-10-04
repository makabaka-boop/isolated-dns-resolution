"""测试夹具：一棵由假权威节点组成的 DNS 树，外加一台“攻击者”节点。

布局（地址只在 FakeNetwork 内路由，绝不会离开测试）：

  10.0.0.1  root   "."
  10.1.1.1  org    "org."            （含指向合法/非法名字的委派与 glue）
  10.2.2.2  net    "net."
  10.3.3.3  example-node  "example.org." + "biz.org."
  10.4.4.4  alias-node    "alias.org." + "target.org." + "loop.org."
  10.6.6.6  attacker      "example.org." 的伪造副本 + "elsewhere.net."
"""
import asyncio
import pytest

from recdns.clock import FakeClock
from recdns.fake import (
    FakeAuthority,
    FakeNetwork,
    FakeTransport,
    Zone,
    rr,
    soa_rr,
    ns_rr,
)
from recdns.resolver import RecursiveResolver, RootHint
import dns.name
import dns.rdatatype


def _root_zone():
    return Zone.build(".", [
        soa_rr(".", minimum=300),
        ns_rr(".", "a.root."),
        rr("a.root.", "A", "10.0.0.1", ttl=3600),
        # TLD 委派
        ns_rr("org.", "ns1.org."),
        rr("ns1.org.", "A", "10.1.1.1", ttl=3600),          # 合法 in-bailiwick glue
        ns_rr("net.", "ns1.net."),
        rr("ns1.net.", "A", "10.2.2.2", ttl=3600),
    ])


def _org_zone():
    return Zone.build("org.", [
        soa_rr("org.", minimum=600),
        ns_rr("org.", "ns1.org."),
        rr("ns1.org.", "A", "10.1.1.1"),
        # example.org：合法 in-bailiwick glue
        ns_rr("example.org.", "ns.example.org."),
        rr("ns.example.org.", "A", "10.3.3.3"),
        # biz.org：只有一个 NS 名 a.elsewhere.net.（out-of-bailiwick）。
        # 父区附加区塞一条指向攻击者 10.6.6.6 的伪造 glue，解析器必须
        # 忽略它，从根独立解析 a.elsewhere.net.（真实地址 10.2.2.10，
        # 该地址上的 net 节点不承载 biz.org -> 另备一台 biz 权威节点
        # 10.7.7.7，elsewhere.net 提供到它的 glue）。
        ns_rr("biz.org.", "a.elsewhere.net."),
        rr("a.elsewhere.net.", "A", "10.6.6.6"),
        # alias / target / loop 区的合法委派（各自独立权威节点）
        ns_rr("alias.org.", "ns.alias.org."),
        rr("ns.alias.org.", "A", "10.4.4.4"),
        ns_rr("target.org.", "ns.target.org."),
        rr("ns.target.org.", "A", "10.4.4.5"),
        ns_rr("loop.org.", "ns.loop.org."),
        rr("ns.loop.org.", "A", "10.4.4.6"),
        # deep.org：用于八跳链路（每一级由独立区承载，节点地址 10.5.5.N）
        ns_rr("deep.org.", "ns.deep.org."),
        rr("ns.deep.org.", "A", "10.5.5.0"),
    ])


def _net_zone():
    return Zone.build("net.", [
        soa_rr("net.", minimum=900),
        ns_rr("net.", "ns1.net."),
        rr("ns1.net.", "A", "10.2.2.2"),
        # elsewhere.net 委派；a.elsewhere.net 是其权威，真实地址 10.7.7.7
        # （与 org 区伪造的 10.6.6.6 不同），由 elsewhere 区提供 glue。
        ns_rr("elsewhere.net.", "a.elsewhere.net."),
        rr("a.elsewhere.net.", "A", "10.7.7.7"),
    ])


def _elsewhere_zone():
    return Zone.build("elsewhere.net.", [
        soa_rr("elsewhere.net.", minimum=300,
               nsname="a.elsewhere.net."),
        ns_rr("elsewhere.net.", "a.elsewhere.net."),
        rr("a.elsewhere.net.", "A", "10.7.7.7"),
    ])


def _example_zone():
    return Zone.build("example.org.", [
        soa_rr("example.org.", minimum=120),
        ns_rr("example.org.", "ns.example.org."),
        rr("ns.example.org.", "A", "10.3.3.3"),
        rr("www.example.org.", "A", "192.0.2.10", ttl=100),
        rr("nodata.example.org.", "A", "192.0.2.11", ttl=100),
        # 负缓存 TTL 边界：SOA TTL=300 < MINIMUM=1000 -> 300
        # （用独立区 neg1.example.org 承载，SOA TTL 取 300）
    ])


def _biz_zone():
    return Zone.build("biz.org.", [
        soa_rr("biz.org.", minimum=60, nsname="a.elsewhere.net."),
        ns_rr("biz.org.", "a.elsewhere.net."),
        rr("www.biz.org.", "A", "192.0.2.20", ttl=50),
    ])


def _alias_zones():
    alias = Zone.build("alias.org.", [
        soa_rr("alias.org.", minimum=60),
        ns_rr("alias.org.", "ns.alias.org."),
        # 跨区 CNAME：alias.org 区 -> target.org 区
        rr("www.alias.org.", "CNAME", "host.target.org.", ttl=40),
        # 自环
        rr("self.alias.org.", "CNAME", "self.alias.org.", ttl=40),
    ])
    target = Zone.build("target.org.", [
        soa_rr("target.org.", minimum=60),
        ns_rr("target.org.", "ns.target.org."),
        rr("host.target.org.", "A", "192.0.2.30", ttl=45),
    ])
    loop = Zone.build("loop.org.", [
        soa_rr("loop.org.", minimum=60),
        ns_rr("loop.org.", "ns.loop.org."),
        # 两环：loopa -> loopb -> loopa
        rr("loopa.loop.org.", "CNAME", "loopb.loop.org.", ttl=40),
        rr("loopb.loop.org.", "CNAME", "loopa.loop.org.", ttl=40),
    ])
    return alias, target, loop


def _attacker_zone():
    # 攻击者也声称自己是 example.org，并给出错误数据。
    return Zone.build("example.org.", [
        soa_rr("example.org."),
        ns_rr("example.org.", "ns.example.org."),
        rr("ns.example.org.", "A", "10.6.6.6"),
        rr("www.example.org.", "A", "203.0.113.66", ttl=10),
    ])


def _neg_zones():
    # SOA RR TTL=300, MINIMUM=1000 -> 负缓存 300
    neg1 = Zone.build("neg1.example.org.", [
        soa_rr("neg1.example.org.", ttl=300, minimum=1000,
               nsname="ns.example.org."),
        ns_rr("neg1.example.org.", "ns.example.org."),
        rr("present.neg1.example.org.", "A", "192.0.2.40", ttl=200),
    ])
    # SOA TTL=2000, MINIMUM=50 -> 负缓存 50
    neg2 = Zone.build("neg2.example.org.", [
        soa_rr("neg2.example.org.", ttl=2000, minimum=50,
               nsname="ns.example.org."),
        ns_rr("neg2.example.org.", "ns.example.org."),
        rr("present.neg2.example.org.", "A", "192.0.2.41", ttl=200),
    ])
    return neg1, neg2


def _deep_zones():
    """生成严格嵌套的长委派链。

    区顶点依次为：deep.org -> a.deep.org -> b.a.deep.org ->
    c.b.a.deep.org -> ...，共 10 级；目标 x.<第9级> 需要
    root/org 之后再走 10 跳，必然越过八跳上限。
    """
    labels = list("abcdefghi")  # a..i，9 个嵌套子区
    zones = []

    def apex_of(i: int) -> str:
        if i == 0:
            return "deep.org."
        # 嵌套：1->a, 2->b.a, 3->c.b.a ...
        return ".".join(reversed(labels[:i])) + ".deep.org."

    def ns_of(i: int) -> str:
        return f"ns.{apex_of(i)}"

    def ip_of(i: int) -> str:
        return f"10.5.5.{i}"

    # 第 0 级 deep.org（NS ns.deep.org 的 glue 在 org 区指向 10.5.5.0）
    z0_rrsets = [
        soa_rr("deep.org.", minimum=30),
        ns_rr("deep.org.", "ns.deep.org."),
        rr("ns.deep.org.", "A", "10.5.5.0"),
        ns_rr(apex_of(1), ns_of(1)),
        rr(ns_of(1), "A", ip_of(1)),
    ]
    zones.append(Zone.build("deep.org.", z0_rrsets))

    for i in range(1, len(labels) + 1):
        apex = apex_of(i)
        rrsets = [
            soa_rr(apex, minimum=30),
            ns_rr(apex, ns_of(i)),
            rr(ns_of(i), "A", ip_of(i)),
        ]
        if i < len(labels):
            nxt = apex_of(i + 1)
            rrsets += [
                ns_rr(nxt, ns_of(i + 1)),
                rr(ns_of(i + 1), "A", ip_of(i + 1)),
            ]
        else:
            rrsets.append(rr(f"x.{apex}", "A", "192.0.2.99", ttl=10))
        zones.append(Zone.build(apex, rrsets))

    return zones


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def env(clock):
    import types
    net = FakeNetwork()

    root_node = FakeAuthority("root", [_root_zone()])
    org_node = FakeAuthority("org", [_org_zone()])
    net_node = FakeAuthority("net", [_net_zone()])
    example_node = FakeAuthority(
        "example", [_example_zone(), *_neg_zones()]
    )
    # 越权 NS 名字解析后到达的真实权威节点：同时承载 elsewhere.net 与 biz.org。
    biz_node = FakeAuthority("biz", [_elsewhere_zone(), _biz_zone()])
    alias, target, loopz = _alias_zones()
    alias_node = FakeAuthority("alias", [alias])
    target_node = FakeAuthority("target", [target])
    loop_node = FakeAuthority("loop", [loopz])
    deep_zones = _deep_zones()
    attacker_node = FakeAuthority("attacker", [_attacker_zone()])

    net.add_node("10.0.0.1", root_node)
    net.add_node("10.1.1.1", org_node)
    net.add_node("10.2.2.2", net_node)
    net.add_node("10.3.3.3", example_node)
    net.add_node("10.7.7.7", biz_node)
    net.add_node("10.4.4.4", alias_node)
    net.add_node("10.4.4.5", target_node)
    net.add_node("10.4.4.6", loop_node)
    for i, z in enumerate(deep_zones):
        addr = f"10.5.5.{i}"
        node = FakeAuthority(f"deep{i}", [z])
        net.add_node(addr, node)
        if i == 0:
            deep_node = node
    net.add_node("10.6.6.6", attacker_node)

    resolver = RecursiveResolver(
        [RootHint("10.0.0.1")],
        FakeTransport(net),
        clock=clock,
    )
    return types.SimpleNamespace(
        net=net,
        resolver=resolver,
        clock=clock,
        root=root_node,
        org=org_node,
        netns=net_node,
        example=example_node,
        biz=biz_node,
        alias=alias_node,
        target=target_node,
        loop=loop_node,
        deep=deep_node,
        attacker=attacker_node,
    )
