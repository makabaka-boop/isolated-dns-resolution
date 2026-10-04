# recdns — 受控测试权威的 asyncio 递归解析器

一个只服务于**隔离测试权威集群**的递归解析服务，基于 `asyncio` 与
[dnspython](https://www.dnspython.org/)。范围刻意收窄：

- 查询类型仅 **A / CNAME / NS / SOA**（类固定 IN）；
- 从配置的根提示逐级跟随委派，**最多八跳**；
- 附加区地址只有在**属于所委派区域且对应某个 NS 服务器名**时才作为 glue，
  其余一律忽略，NS 名从根独立解析；
- CNAME 环检测（自环、跨节点环）；
- UDP 收到 `TC=1` 后自动用 **TCP** 重试；
- 正缓存按 TTL 失效；**NXDOMAIN 按名称**缓存、**NODATA 按 (名称, 类型)**
  缓存，负缓存期限取 `min(SOA RR TTL, SOA MINIMUM)`；
- 相同查询**共享正在进行的上游请求**，单个等待者取消只摘除自己，
  共享任务与其他等待者不受影响（即使全部等待者都取消，任务仍完成并写缓存）。

## 模块

| 文件 | 职责 |
| --- | --- |
| `recdns/resolver.py` | 递归主循环、委派跟随、CNAME 环检测、在途请求共享 |
| `recdns/cache.py` | 正缓存（RRset/TTL）与负缓存（NXDOMAIN/NODATA） |
| `recdns/clock.py` | `AsyncioClock`（生产）与 `FakeClock`（可控虚拟时钟） |
| `recdns/transport.py` | `RealTransport`：UDP + TC 后 TCP 回退，地址白名单 |
| `recdns/fake.py` | 假权威节点 `FakeAuthority`、内存网络、挂起/放行闸门 |
| `recdns/errors.py` | 异常类型 |

## glue 采信规则

对于 referral `authority` 中的 NS RRset 与 `additional` 段：

1. `additional` 里的 A 必须属主名**等于某个 NS rdata 的目标名**；
2. 该目标名必须**位于被委派区域内**（是 cut 的子域，含 cut apex）；
3. 两条同时满足才直接用作下一跳地址；否则忽略该地址，
   从根开始独立解析该 NS 名的 A（独立递归，同样受 glue 栈保护）；
4. glue 名解析链上出现重复名字（自引用/互引用）立即失败，
   不会无限递归，也不会向配置外地址发包。

`RealTransport(allowed={...})` 在发包前校验服务器地址，
未登记地址直接拒绝——服务绝不会访问配置范围之外的主机。

## 测试

```
python3 -m pytest tests/ -q
```

测试全部运行在内存假网络上（`test_real_transport.py` 使用 127.0.0.1
临时端口验证真实 socket 的 UDP→TCP 路径），覆盖：

- 基本解析、NS/SOA apex、八跳边界（恰好 8 跳成功、第 9 跳失败）；
- **伪造 glue**：越权 glue（指向攻击者节点）被忽略后从根重解析、
  “同区但不对应 NS 名”的诱饵地址不被使用、自引用 glue 立即报错；
- **别名链**：跨权威节点的 CNAME 链、链上正缓存、自环与两节点环；
- **负缓存边界**：NXDOMAIN 按名称对所有类型生效、NODATA 按 (名, 类型)、
  `min(SOA TTL, MINIMUM)` 的两种取值（300 与 50）、边界时刻失效；
- UDP 截断 → TCP 重试；
- **取消竞争**：相同查询合并为一次上游访问、取消一个/全部等待者
  不影响共享任务，结果在任务完成后进入缓存；
- 可控时钟：到期顺序、推进后唤醒、取消不波及其他定时器。

### 假权威拓扑

```
10.0.0.1  root      "."
10.1.1.1  org       "org."   （含伪造 out-of-bailiwick glue 指向 10.6.6.6）
10.2.2.2  net       "net."   （给出越权 NS 名的真实 glue 10.7.7.7）
10.3.3.3  example   example.org 与两个负缓存边界区
10.7.7.7  biz       elsewhere.net + biz.org（伪造 glue 永远到不了这里）
10.4.4.4/5/6        alias / target / loop 三个独立别名权威
10.5.5.0..9         嵌套九级委派链（用于八跳上限）
10.6.6.6  attacker  自称 example.org 的攻击者权威（断言从未被访问）
```

## 使用示例

```python
from recdns import RecursiveResolver, RootHint
from recdns.transport import RealTransport

resolver = RecursiveResolver(
    root_hints=[RootHint("10.0.0.1")],
    transport=RealTransport(allowed={"10.0.0.1", "10.1.1.1", "10.3.3.3"}),
)

answer = await resolver.resolve("www.example.org.", "A")
if answer.rcode == 0:                 # NOERROR
    for rrset in answer.chain: ...   # CNAME 链 + 末端 RRset
```
