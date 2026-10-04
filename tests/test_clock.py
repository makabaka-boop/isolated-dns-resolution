"""可控时钟：时间只在 advance 中流逝，定时器按序触发。"""
import asyncio
import pytest

from recdns.clock import FakeClock

pytestmark = pytest.mark.asyncio


async def test_sleep_completes_after_advance():
    clock = FakeClock()
    fired = []

    async def waiter():
        await clock.sleep(10)
        fired.append(clock.time())

    task = asyncio.ensure_future(waiter())
    for _ in range(5):
        await asyncio.sleep(0)
    assert fired == []  # 时间未推进

    await clock.advance(9)
    assert fired == []
    await clock.advance(1)
    await asyncio.sleep(0)
    assert fired == [10.0]
    assert task.done() and not task.cancelled()


async def test_timers_fire_in_expiry_order():
    clock = FakeClock()
    order = []

    async def waiter(tag, delay):
        await clock.sleep(delay)
        order.append(tag)

    asyncio.ensure_future(waiter("late", 30))
    asyncio.ensure_future(waiter("early", 5))
    asyncio.ensure_future(waiter("mid", 20))
    await clock.advance(30)
    assert order == ["early", "mid", "late"]


async def test_sleep_cancellation_does_not_block_others():
    clock = FakeClock()
    fired = []

    async def w(tag, delay):
        await clock.sleep(delay)
        fired.append(tag)

    t1 = asyncio.ensure_future(w("a", 10))
    t2 = asyncio.ensure_future(w("b", 10))
    for _ in range(5):
        await asyncio.sleep(0)
    t1.cancel()
    with pytest.raises(asyncio.CancelledError):
        await t1

    await clock.advance(10)
    assert fired == ["b"]
