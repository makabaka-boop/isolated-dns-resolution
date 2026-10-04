"""UDP 截断（TC=1）后自动用 TCP 重试。"""
import dns.rdatatype
import pytest

pytestmark = pytest.mark.asyncio


async def test_truncated_udp_falls_back_to_tcp(env):
    # 让 example 权威对 A 查询先发一次 UDP 截断。
    env.example.truncate_types = {dns.rdatatype.A}

    answer = await env.resolver.resolve("www.example.org.", "A")
    assert {a.address for a in answer.found_rrset} == {"192.0.2.10"}

    protos = [p for _q, _t, p in env.example.calls]
    # 先收到 TC，再用 TCP 拿到完整应答。
    assert protos.count("UDP-TC") == 1
    assert protos.count("TCP") >= 1

    # 结果正常进缓存：第二次不再经过传输。
    env.example.calls.clear()
    cached = await env.resolver.resolve("www.example.org.", "A")
    assert cached.cached
    assert env.example.calls == []
