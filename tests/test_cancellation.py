"""相同查询共享在途上游请求；单个等待者取消不影响其他等待者与共享任务。"""
import asyncio
import dns.rdatatype
import pytest

from recdns.fake import QueryGate

pytestmark = pytest.mark.asyncio


async def test_concurrent_identical_queries_share_one_upstream(env):
    gate = QueryGate().holds(
        lambda q, t: t == dns.rdatatype.A
        and q.to_text() == "www.example.org."
    )
    env.example.gate = gate

    tasks = [
        asyncio.ensure_future(env.resolver.resolve("www.example.org.", "A"))
        for _ in range(3)
    ]
    for _ in range(20):
        await asyncio.sleep(0)
    assert len(gate.pending()) == 1
    gate.release_all()

    results = await asyncio.gather(*tasks)
    assert all(r.rcode == 0 for r in results)
    # 三个等待者 -> 权威只被查询一次。
    example_hits = [
        c for c in env.example.calls
        if c[1] == dns.rdatatype.A
    ]
    assert len(example_hits) == 1


async def test_cancelling_one_waiter_keeps_others_and_the_query(env):
    gate = QueryGate().holds(
        lambda q, t: t == dns.rdatatype.A
        and q.to_text() == "www.example.org."
    )
    env.example.gate = gate

    t1 = asyncio.ensure_future(env.resolver.resolve("www.example.org.", "A"))
    t2 = asyncio.ensure_future(env.resolver.resolve("www.example.org.", "A"))
    t3 = asyncio.ensure_future(env.resolver.resolve("www.example.org.", "A"))

    # 让三个协程都跑到挂起点并共享同一个在途查询。
    for _ in range(20):
        await asyncio.sleep(0)
    assert len(gate.pending()) == 1

    # 取消一个等待者：共享查询与其他等待者必须不受影响。
    t2.cancel()
    with pytest.raises(asyncio.CancelledError):
        await t2
    assert not t1.done() and not t3.done()

    n = gate.release_all()
    assert n == 1

    a1, a3 = await asyncio.gather(t1, t3)
    assert {a.address for a in a1.found_rrset} == {"192.0.2.10"}
    assert {a.address for a in a3.found_rrset} == {"192.0.2.10"}

    # 共享任务已把结果写入缓存：后续查询不再访问权威。
    env.example.calls.clear()
    cached = await env.resolver.resolve("www.example.org.", "A")
    assert cached.cached
    assert env.example.calls == []


async def test_cancelling_all_waiters_does_not_cancel_shared_task(env):
    gate = QueryGate().holds(
        lambda q, t: t == dns.rdatatype.A
        and q.to_text() == "www.example.org."
    )
    env.example.gate = gate

    t1 = asyncio.ensure_future(env.resolver.resolve("www.example.org.", "A"))
    t2 = asyncio.ensure_future(env.resolver.resolve("www.example.org.", "A"))
    for _ in range(20):
        await asyncio.sleep(0)
    assert len(gate.pending()) == 1

    t1.cancel()
    t2.cancel()
    with pytest.raises(asyncio.CancelledError):
        await t1
    with pytest.raises(asyncio.CancelledError):
        await t2

    # 共享任务仍在（等待者全部离开后它继续把权威应答取回并写缓存）。
    gate.release_all()
    for _ in range(20):
        await asyncio.sleep(0)

    answer = await env.resolver.resolve("www.example.org.", "A")
    assert answer.cached
    assert {a.address for a in answer.found_rrset} == {"192.0.2.10"}
