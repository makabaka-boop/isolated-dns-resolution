"""解析器可能抛出的异常。"""


class DNSError(Exception):
    """解析器错误基类。"""


class UpstreamError(DNSError):
    """上游权威服务器无法给出可用响应（超时、连接失败、所有服务器失败）。"""


class InvalidResponseError(DNSError):
    """上游返回了解析器无法接受的畸形/不可信响应。"""


class ResolutionLimitError(DNSError):
    """委派跟随超过最大跳数（八跳），或 glue 解析陷入自引用。"""


class CNAMELoopError(DNSError):
    """CNAME 链出现环。"""

    def __init__(self, name, chain):
        self.name = name
        self.chain = list(chain)
        super().__init__(
            f"CNAME loop detected at {name}: "
            + " -> ".join(str(n) for n in self.chain)
        )


class UnsupportedQueryError(DNSError):
    """查询类型超出服务范围（只支持 A/CNAME/NS/SOA）。"""
