"""只与配置内测试权威服务器通信的极简递归解析器。

范围：A / CNAME / NS / SOA（类固定 IN），从配置根提示逐级跟随委派，
最多八跳；仅在附加区地址属于所委派区域且与服务器名称对应时才作为 glue。
"""
from .errors import (
    DNSError,
    UpstreamError,
    InvalidResponseError,
    ResolutionLimitError,
    CNAMELoopError,
    UnsupportedQueryError,
)
from .resolver import Answer, RecursiveResolver, RootHint
from .cache import Cache
from .clock import AsyncioClock, FakeClock

__all__ = [
    "Answer",
    "RecursiveResolver",
    "RootHint",
    "Cache",
    "AsyncioClock",
    "FakeClock",
    "DNSError",
    "UpstreamError",
    "InvalidResponseError",
    "ResolutionLimitError",
    "CNAMELoopError",
    "UnsupportedQueryError",
]
