#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
日志分析小工具 (log_analyzer)
=============================

读取日志文件，统计 ERROR 出现次数，并给出有用的上下文信息。

功能
----
1. 统计 ERROR 出现次数（可自定义关键字 / 自定义日志级别）
2. 各日志级别分布（ERROR / WARN / INFO / DEBUG ...）
3. TOP N 高频错误（自动把时间戳、数字、ID 归一化后聚类，避免同类错误被拆散）
4. 打印错误样例行（含行号）
5. 按时间桶统计错误趋势（--timeline）
6. 输出 JSON（--json），方便接入其它系统
7. 大文件友好：逐行流式读取，不会一次性把整个文件读进内存

用法示例
--------
    python log_analyzer.py app.log
    python log_analyzer.py app.log --keyword Exception --top 5
    python log_analyzer.py app.log --level            # 看全部级别分布
    python log_analyzer.py app.log --timeline         # 看错误随时间分布
    python log_analyzer.py app.log --json             # 机器可读输出
    python log_analyzer.py app.log --fail-on-error    # 有错误则退出码 1（可用于 CI）
    type app.log | python log_analyzer.py -           # 从标准输入读取
"""

from __future__ import annotations

import argparse
import io
import json
import re
import sys
from collections import Counter
from typing import Iterable, Iterator, TextIO

__version__ = "1.0.0"

# ---------------------------------------------------------------- 常量定义

# 常见日志级别（按优先级从高到低），用于统计分布
LEVELS = ("FATAL", "CRITICAL", "ERROR", "WARN", "WARNING", "INFO", "DEBUG", "TRACE")

# 一行日志里出现级别单词即认为属于该级别，避免匹配到 "error_code" 之类的字段
LEVEL_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?P<level>" + "|".join(LEVELS) + r")(?![A-Za-z0-9_])"
)

# 时间戳：支持 2026-10-07 15:42:57 / 2026-10-07T15:42:57 / 2026/10/07 15:42:57
TS_RE = re.compile(
    r"(?P<date>\d{4}[-/]\d{2}[-/]\d{2})[T ](?P<hour>\d{2}):(?P<minute>\d{2})"
)

# 归一化用的替换规则：把易变的部分抹掉，让同类错误能被聚到一起
NORMALIZE_RULES = (
    (TS_RE, "<TS>"),
    (re.compile(r"\b[0-9a-fA-F]{8,}\b"), "<HEX>"),          # trace id / md5
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<IP>"),     # IP
    (re.compile(r"\b\d+\b"), "<N>"),                          # 普通数字
    (re.compile(r"\s+"), " "),
)

# Windows 上中文日志常见 GBK 编码，按顺序尝试
ENCODINGS = ("utf-8-sig", "utf-8", "gbk", "latin-1")


# ---------------------------------------------------------------- 基础工具

def detect_encoding(raw: io.BufferedReader, probe_size: int = 65536) -> str:
    """只读文件开头一小段用于探测编码，然后把指针复位，保证后续仍是流式读取。"""
    probe = raw.read(probe_size)
    raw.seek(0)
    for enc in ENCODINGS:
        try:
            probe.decode(enc)
            return enc
        except UnicodeDecodeError:
            continue
    return "utf-8"


def open_log(path: str) -> TextIO:
    """打开日志文件，自动探测常见编码；path 为 '-' 时读取标准输入。

    全程流式读取，内存占用与文件大小无关，GB 级日志也能跑。
    """
    if path == "-":
        return sys.stdin

    raw = open(path, "rb")
    try:
        enc = detect_encoding(raw)
    except Exception:
        raw.close()
        raise
    return io.TextIOWrapper(raw, encoding=enc, errors="replace")


def read_lines(source: TextIO) -> Iterator[str]:
    for line in source:
        yield line.rstrip("\r\n")


def normalize(message: str) -> str:
    """把日志行归一化成模版，用于高频错误聚类。"""
    out = message
    for pattern, repl in NORMALIZE_RULES:
        out = pattern.sub(repl, out)
    return out.strip()[:200]


# ---------------------------------------------------------------- 核心统计

class LogStats:
    """日志统计结果容器。"""

    def __init__(self) -> None:
        self.total_lines = 0
        self.matched = 0                       # 命中关键字的行数
        self.level_counts: Counter[str] = Counter()
        self.pattern_counts: Counter[str] = Counter()   # 归一化后的错误模版
        self.samples: list[dict] = []          # 前若干条命中行
        self.timeline: Counter[str] = Counter()         # 时间桶 -> 命中数
        self.missing_timestamp = 0             # 命中但解析不出时间的行数

    def as_dict(self, keyword: str, top: int, sample_limit: int) -> dict:
        return {
            "keyword": keyword,
            "total_lines": self.total_lines,
            "matched_lines": self.matched,
            "error_rate": round(self.matched / self.total_lines, 4) if self.total_lines else 0.0,
            "level_counts": dict(self.level_counts.most_common()),
            "top_patterns": [
                {"count": c, "pattern": p} for p, c in self.pattern_counts.most_common(top)
            ],
            "timeline": dict(sorted(self.timeline.items())),
            "samples": self.samples[:sample_limit],
        }


def analyze(
    source: TextIO,
    keyword: str,
    regex: bool = False,
    context: int = 0,
) -> LogStats:
    """逐行扫描日志，返回统计结果。"""
    stats = LogStats()

    if regex:
        matcher = re.compile(keyword, re.IGNORECASE)
        hit = lambda line: bool(matcher.search(line))      # noqa: E731
    else:
        needle = keyword.lower()
        hit = lambda line: needle in line.lower()          # noqa: E731

    recent: list[str] = []       # 保留最近若干行，用于打印上下文
    pending_context = 0          # 还需要为已命中的行补几行后续上下文

    for lineno, line in enumerate(read_lines(source), start=1):
        stats.total_lines += 1

        m = LEVEL_RE.search(line)
        if m:
            level = m.group("level").upper()
            stats.level_counts["WARN" if level == "WARNING" else level] += 1

        if hit(line):
            stats.matched += 1
            stats.pattern_counts[normalize(line)] += 1

            ts = TS_RE.search(line)
            if ts:
                stats.timeline[f"{ts.group('hour')}:{ts.group('minute')}"] += 1
            else:
                stats.missing_timestamp += 1

            if len(stats.samples) < 20:
                stats.samples.append({
                    "line": lineno,
                    "text": line[:300],
                    "before": list(recent[-context:]) if context else [],
                    "after": [],
                })
            if context:
                pending_context = context

        elif pending_context > 0 and stats.samples:
            stats.samples[-1]["after"].append(line)
            pending_context -= 1

        recent.append(line)
        if len(recent) > max(context, 1):
            recent.pop(0)

    return stats


# ---------------------------------------------------------------- 输出渲染

BAR_WIDTH = 24


def bar(count: int, largest: int) -> str:
    if largest <= 0:
        return ""
    filled = max(1, round(count / largest * BAR_WIDTH))
    return "█" * filled


def render_text(args: argparse.Namespace, stats: LogStats) -> str:
    """把统计结果渲染成终端友好的文本。"""
    out: list[str] = []
    add = out.append

    add("=" * 62)
    add(f" 日志分析报告  |  文件: {args.logfile}")
    add("=" * 62)

    rate = f"{stats.matched / stats.total_lines:.2%}" if stats.total_lines else "0.00%"
    add(f"总行数      : {stats.total_lines:,}")
    add(f"{args.keyword!r} 命中: {stats.matched:,}  ({rate} of 全部行)")
    add("")

    if args.level:
        add("-- 日志级别分布 " + "-" * 44)
        if stats.level_counts:
            largest = max(stats.level_counts.values())
            for lvl, cnt in stats.level_counts.most_common():
                mark = "  <==" if lvl == args.keyword.upper() else ""
                add(f"  {lvl:<8} {cnt:>8,}  {bar(cnt, largest)}{mark}")
        else:
            add("  (未识别到日志级别，可用 --keyword 指定关键字)")
        add("")

    if stats.pattern_counts:
        add(f"-- TOP {args.top} 高频错误（已归一化） " + "-" * 27)
        largest = stats.pattern_counts.most_common(1)[0][1]
        for idx, (pat, cnt) in enumerate(stats.pattern_counts.most_common(args.top), 1):
            add(f"  {idx}. [{cnt:>5,} 次] {bar(cnt, largest)}")
            add(f"     {pat}")
        add("")

    if args.timeline and stats.timeline:
        add("-- 错误时间分布（HH:MM 分钟桶） " + "-" * 30)
        largest = max(stats.timeline.values())
        for bucket, cnt in sorted(stats.timeline.items()):
            add(f"  {bucket}  {cnt:>5,}  {bar(cnt, largest)}")
        if stats.missing_timestamp:
            add(f"  （另有 {stats.missing_timestamp:,} 行未解析出时间戳，已跳过）")
        add("")

    if stats.samples:
        shown = stats.samples[: args.samples]
        add(f"-- 错误样例（显示前 {len(shown)} / {stats.matched} 条） " + "-" * 22)
        for s in shown:
            for ctx in s["before"]:
                add(f"     {ctx[:160]}")
            add(f"  L{s['line']:<6} {s['text']}")
            for ctx in s["after"]:
                add(f"     {ctx[:160]}")
            if args.context:
                add("")
        add("")

    verdict = "发现错误，建议排查" if stats.matched else "未发现错误，日志正常"
    add(f"[结论] {verdict}")
    return "\n".join(out)


# ---------------------------------------------------------------- CLI 入口

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="log_analyzer",
        description="读取日志文件，统计 ERROR 出现次数并输出分析报告。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例:\n"
               "  python log_analyzer.py app.log\n"
               "  python log_analyzer.py app.log --level --timeline --top 5\n"
               "  python log_analyzer.py app.log --regex \"timeout|refused\"\n"
               "  python log_analyzer.py app.log --json > report.json\n",
    )
    p.add_argument("logfile", help="日志文件路径，'-' 表示从标准输入读取")
    p.add_argument("-k", "--keyword", default="ERROR",
                   help="要统计的关键字，默认 ERROR（不区分大小写）")
    p.add_argument("-r", "--regex", action="store_true",
                   help="把 --keyword 当作正则表达式处理")
    p.add_argument("-l", "--level", action="store_true",
                   help="额外输出各日志级别的分布")
    p.add_argument("-t", "--top", type=int, default=10,
                   help="输出前 N 条高频错误模版，默认 10")
    p.add_argument("--timeline", action="store_true",
                   help="按分钟统计错误的时间分布")
    p.add_argument("-c", "--context", type=int, default=0,
                   help="每条样例行额外打印前后各 N 行上下文")
    p.add_argument("-s", "--samples", type=int, default=5,
                   help="最多展示多少条错误样例，默认 5")
    p.add_argument("--json", action="store_true", dest="as_json",
                   help="以 JSON 格式输出结果")
    p.add_argument("--fail-on-error", action="store_true",
                   help="命中数大于 0 时以退出码 1 结束（适合 CI / 巡检脚本）")
    p.add_argument("-V", "--version", action="version",
                   version=f"%(prog)s {__version__}")
    return p


def no_args_hint() -> int:
    """没有传任何参数时，打印友好的中文引导（而不是 argparse 的英文报错）。"""
    print(__doc__ or "")
    print("=" * 62)
    print(" 你还没有指定要分析的日志文件")
    print("=" * 62)
    print("命令行用法:")
    print("    python log_analyzer.py <日志文件路径> [选项]")
    print("    例: python log_analyzer.py C:\\logs\\app.log")
    print()
    print("PyCharm 用户:")
    print("    1. 右上角 运行配置 -> Edit Configurations...")
    print("    2. 在 Parameters（形参/参数）一栏填入日志路径，例如:")
    print("           sample.log --level --top 5")
    print("    3. 也可以直接在 Terminal 面板里运行上面的命令行")
    print()
    print("提示: 传 '-' 可从标准输入读取, 例如 type app.log | python log_analyzer.py -")
    return 2


def main(argv: Iterable[str] | None = None) -> int:
    if argv is None and len(sys.argv) == 1:
        # 仅当用户一个参数都没给（典型场景：IDE 里直接点运行）才走引导
        return no_args_hint()

    args = build_parser().parse_args(argv)

    try:
        source = open_log(args.logfile)
    except FileNotFoundError:
        print(f"[错误] 找不到文件: {args.logfile}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"[错误] 无法读取文件: {exc}", file=sys.stderr)
        return 2

    try:
        stats = analyze(source, args.keyword, regex=args.regex, context=args.context)
    except re.error as exc:
        print(f"[错误] 非法的正则表达式 {args.keyword!r}: {exc}", file=sys.stderr)
        return 2
    finally:
        if source is not sys.stdin:
            source.close()

    if args.as_json:
        payload = stats.as_dict(args.keyword, args.top, args.samples)
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(render_text(args, stats))

    if args.fail_on_error and stats.matched > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
