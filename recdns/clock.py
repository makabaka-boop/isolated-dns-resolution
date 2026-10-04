"""可控时钟抽象。

生产环境使用 :class:`AsyncioClock`（基于事件循环的单调时钟）；
测试使用 :class:`FakeClock`，时间只在 ``advance`` / ``sleep`` 中流逝，
定时器按到期顺序同步触发，到期任务通过反复让出事件循环获得运行机会。
"""
import asyncio
import heapq


class AsyncioClock:
    def time(self) -> float:
        return asyncio.get_running_loop().time()

    async def sleep(self, delay: float) -> None:
        await asyncio.sleep(delay)


class FakeClock:
    """手动推进的时钟。

    - :meth:`time` 返回当前虚拟时间；
    - :meth:`sleep` 登记定时器，到点的回调在事件循环上按序执行；
    - :meth:`advance` 把时间推进 ``delta``，然后反复让出事件循环，
      让因定时器到期而就绪的协程能走到下一次挂起点。
    """

    def __init__(self, start: float = 0.0):
        self._now = float(start)
        self._timers = []          # (expire, seq, callback)
        self._seq = 0

    def time(self) -> float:
        return self._now

    async def sleep(self, delay: float) -> None:
        if delay <= 0:
            await asyncio.sleep(0)
            return
        loop = asyncio.get_running_loop()
        self._seq += 1
        event = asyncio.Event()
        heapq.heappush(self._timers, (self._now + delay, self._seq, event.set))
        try:
            await event.wait()
        except asyncio.CancelledError:
            # 等待者被取消：定时器回调留着也无害（set 一个无人等待的事件），
            # 但为了可观察性，直接让它在未来到点空转即可。
            raise

    async def advance(self, delta: float, *, pumps: int = 400) -> None:
        """推进虚拟时间并驱动到期任务。

        每弹出一个到期定时器就让出一次事件循环，使等待协程严格按到期
        顺序唤醒，并能在唤醒后继续登记后续定时器（链上 sleep）。
        ``pumps`` 是总让出次数上限；解析链路每跳只需常数次让出。
        """
        target = self._now + delta
        idle = 0
        for _ in range(pumps):
            size_before = len(self._timers)
            popped = False
            if self._timers and self._timers[0][0] <= target:
                expire, _seq, cb = heapq.heappop(self._timers)
                self._now = expire  # 先走到到期时刻，再触发回调
                cb()
                popped = True
            await asyncio.sleep(0)
            grew = len(self._timers) > max(size_before - (1 if popped else 0), 0)
            due_waiting = bool(self._timers and self._timers[0][0] <= target)
            if popped or grew or due_waiting:
                idle = 0          # 有进展或还有活干
            else:
                idle += 1         # 让出后系统仍空闲
                if idle >= 2:     # 连续两轮空闲：协程都已挂起
                    break
        self._now = target
