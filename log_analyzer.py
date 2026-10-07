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
8. 服务器友好：可直接传目录（自动取最新日志）、支持 .gz 轮转文件、支持多文件合并统计

用法示例
--------
    # 本地 / 单文件
    python log_analyzer.py app.log
    python log_analyzer.py app.log --keyword Exception --top 5
    python log_analyzer.py app.log --level            # 看全部级别分布
    python log_analyzer.py app.log --timeline         # 看错误随时间分布
    python log_analyzer.py app.log --json             # 机器可读输出
    python log_analyzer.py app.log --fail-on-error    # 有错误则退出码 1（可用于 CI）
    type app.log | python log_analyzer.py -           # 从标准输入读取

    # 服务器 / 目录（自动挑最新那个 .log，并提示选了哪个）
    python3 log_analyzer.py /data/cloudpivot/program/backEnd/webapi/logs/

    # 合并统计多天日志 + 压缩包
    python3 log_analyzer.py /path/to/logs/ --merge
    python3 log_analyzer.py webapi.log webapi.log.2026-10-06.gz

    # 只看最近 5 万行（服务器上大文件常用做法，需要可用 tail）
    tail -n 50000 /path/to/webapi.log | python3 log_analyzer.py -
"""


from __future__ import annotations

import argparse
import contextlib
import difflib
import gzip
import io
import itertools
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Iterable, Iterator, TextIO

__version__ = "1.1.0"

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

# 认定为日志文件的扩展名（用于目录扫描）
LOG_SUFFIXES = (".log", ".txt", ".out")

# 辅助日志：GC 日志、崩溃转储、锁文件等，扫目录时默认跳过，避免污染业务日志统计。
# 注意：如果用户直接写出文件名，则照常分析，不做拦截。
AUX_RE = re.compile(
    r"(^gc\.log|^hs_err_pid|^stdout|^stderr|\.current$|\.tmp$|\.lck$|\.lock$|\.idx$|\.pid$)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------- 路径解析

def is_log_file(name: str) -> bool:
    """判断文件名是不是日志，兼容 webapi.log.2026-10-06 和 xxx.log.gz 这类轮转命名。"""
    lower = name.lower()
    if lower == "-" or name.startswith("."):
        return False
    return lower.endswith(LOG_SUFFIXES) or ".log." in lower


def is_auxiliary(name: str) -> bool:
    """判断是不是 GC / 临时类辅助日志。"""
    return bool(AUX_RE.search(name))


def pick_primary(candidates: list[Path]) -> Path:
    """从多个日志里挑出最该看的那个。

    优先级（越靠前越优先）:
      1. 正在写的业务日志(如 webapi.log) 优先于轮转归档(webapi.log.2026-10-06)
      2. 修改时间更新的优先
    """
    def rank(f: Path) -> tuple:
        rotated = ".log." in f.name.lower()      # 轮转归档
        return (rotated, -f.stat().st_mtime)

    return min(candidates, key=rank)


def expand_paths(
    paths: Iterable[str],
    pattern: str | None = None,
    merge: bool = False,
) -> tuple[list[str], list[str]]:
    """把用户给的路径（可能是目录、通配符）展开成待分析的文件列表。

    返回 (文件列表, 提示信息列表)。目录默认只取其中最新的业务日志，
    这样在服务器上直接填日志目录也能立刻出结果；merge=True 则合并目录下全部日志。
    """
    files: list[str] = []
    notes: list[str] = []

    for raw in paths:
        if raw == "-":
            files.append(raw)
            continue

        p = Path(raw)

        if p.is_dir():
            all_files = [f for f in p.iterdir() if f.is_file()]
            aux = [f.name for f in all_files if is_log_file(f.name) and is_auxiliary(f.name)]
            candidates = [
                f for f in all_files if is_log_file(f.name) and not is_auxiliary(f.name)
            ]
            if pattern:
                candidates = [f for f in candidates if f.match(pattern)]
            if aux:
                notes.append(
                    f"已跳过 {len(aux)} 个辅助日志(GC/临时文件): "
                    f"{', '.join(sorted(aux)[:5])}"
                    + (" 等" if len(aux) > 5 else "")
                    + "，如需分析请直接指定文件名"
                )
            if not candidates:
                raise FileNotFoundError(f"目录里没找到可分析的日志文件: {raw}")

            if len(candidates) > 1 and not merge:
                chosen = pick_primary(candidates)
                notes.append(
                    f"目录 {raw} 下有 {len(candidates)} 个日志，默认分析: {chosen.name}"
                    f"（加 --merge 可合并全部统计）"
                )
                files.append(str(chosen))
                continue

            candidates.sort(key=lambda f: f.name)
            if len(candidates) > 1:
                notes.append(f"目录 {raw} 下合并统计 {len(candidates)} 个日志文件")
            files.extend(str(f) for f in candidates)
            continue

        if not p.exists():
            # 支持用户自己写通配符，如 /path/logs/webapi.log.*
            hits = sorted(Path().glob(raw)) if any(c in raw for c in "*?[") else []
            if hits:
                files.extend(str(h) for h in hits if h.is_file())
                continue
            raise FileNotFoundError(f"找不到文件或目录: {raw}")

        files.append(str(p))

    return files, notes


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

    支持 .gz 压缩的轮转日志；全程流式读取，内存占用与文件大小无关。
    """
    if path == "-":
        return sys.stdin

    if path.lower().endswith(".gz"):
        raw = gzip.open(path, "rb")           # type: ignore[assignment]
        enc = detect_encoding_gz(path)
        return io.TextIOWrapper(raw, encoding=enc, errors="replace")

    raw = open(path, "rb")
    try:
        enc = detect_encoding(raw)
    except Exception:
        raw.close()
        raise
    return io.TextIOWrapper(raw, encoding=enc, errors="replace")


def detect_encoding_gz(path: str, probe_size: int = 65536) -> str:
    """gzip 不能 seek 回退，因此单独探测：读一小段解压内容后重新打开。"""
    with gzip.open(path, "rb") as fh:
        probe = fh.read(probe_size)
    for enc in ENCODINGS:
        try:
            probe.decode(enc)
            return enc
        except UnicodeDecodeError:
            continue
    return "utf-8"


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
    target = ", ".join(args.logfile)
    if len(args.used_files) > 1:
        target = f"{target}  (共 {len(args.used_files)} 个文件)"
    add(f" 日志分析报告  |  文件: {target}")
    for note in args.file_notes:
        add(f"     - {note}")
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
    p.add_argument("logfile", nargs="+",
                   help="日志文件路径或所在目录（可传多个），'-' 表示从标准输入读取")
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
    p.add_argument("-m", "--merge", action="store_true",
                   help="传目录时合并目录下所有日志一起统计（默认只取最新那个）")
    p.add_argument("--pattern", default=None,
                   help="传目录时只统计匹配该通配符的文件，如 --pattern 'webapi*'")
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


def suggest_similar(raw: str, limit: int = 3) -> list[str]:
    """文件找不到时，在同一个目录里找名字最接近的几个文件，帮用户发现手误。"""
    p = Path(raw)
    try:
        if not (p.parent.is_dir()):
            return []
        names = [f.name for f in p.parent.iterdir() if f.is_file()]
    except OSError:
        return []

    candidates = difflib.get_close_matches(p.name, names, n=limit, cutoff=0.55)
    if not candidates and not p.suffix:
        # 用户漏写扩展名的情况，补上 .log 再比一次
        candidates = difflib.get_close_matches(p.name + ".log", names, n=limit, cutoff=0.55)
    return candidates


def main(argv: Iterable[str] | None = None) -> int:
    if argv is None and len(sys.argv) == 1:
        # 仅当用户一个参数都没给（典型场景：IDE 里直接点运行）才走引导
        return no_args_hint()

    args = build_parser().parse_args(argv)

    # 展开目录 / 通配符，得到真正要读的文件列表
    try:
        files, notes = expand_paths(args.logfile, args.pattern, args.merge)
    except FileNotFoundError as exc:
        print(f"[错误] {exc}", file=sys.stderr)
        first = args.logfile[0] if args.logfile else ""
        if os.name == "nt" and first.startswith("/"):
            print("", file=sys.stderr)
            print("      这个路径以 / 开头，是 Linux 服务器上的路径，", file=sys.stderr)
            print("      而你当前在 Windows 本机运行，本机并没有这个文件。两种做法:", file=sys.stderr)
            print("", file=sys.stderr)
            print("      做法一(推荐): 把脚本传到服务器上直接分析", file=sys.stderr)
            print("          scp log_analyzer.py 用户名@服务器IP:/tmp/", file=sys.stderr)
            print("          ssh 用户名@服务器IP", file=sys.stderr)
            print("          python3 /tmp/log_analyzer.py /data/cloudpivot/program/backEnd/webapi/logs/", file=sys.stderr)
            print("", file=sys.stderr)
            print("      做法二: 先把日志下载到本地，再分析本地文件", file=sys.stderr)
            print("          scp 用户名@服务器IP:/data/cloudpivot/program/backEnd/webapi/logs/log_total.log D:\\logs\\", file=sys.stderr)
            print("          python log_analyzer.py D:\\logs\\log_total.log", file=sys.stderr)
            print("          (图形化工具: WinSCP / Xftp / FinalShell 直接拖拽下载)", file=sys.stderr)
        else:
            print("      提示: 路径要写到具体的日志文件，或直接写日志所在目录", file=sys.stderr)
            similar = suggest_similar(first)
            if similar:
                print("", file=sys.stderr)
                print("      你是不是想找:", file=sys.stderr)
                for name in similar:
                    print(f"        {Path(first).parent / name}", file=sys.stderr)
        return 2
    if not files:
        print("[错误] 没有可分析的日志文件", file=sys.stderr)
        return 2
    args.used_files = files
    args.file_notes = notes

    try:
        # ExitStack 负责统一关闭所有打开的文件；stdin 不关闭
        with contextlib.ExitStack() as stack:
            streams = []
            for path in files:
                if path == "-":
                    streams.append(sys.stdin)
                else:
                    streams.append(stack.enter_context(open_log(path)))
            merged = itertools.chain.from_iterable(streams)
            stats = analyze(merged, args.keyword, regex=args.regex, context=args.context)
    except re.error as exc:
        print(f"[错误] 非法的正则表达式 {args.keyword!r}: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"[错误] 无法读取日志文件: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\n[中断] 已取消", file=sys.stderr)
        return 130

    if args.as_json:
        payload = stats.as_dict(args.keyword, args.top, args.samples)
        payload["files"] = files
        payload["notes"] = notes
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(render_text(args, stats))

    if args.fail_on_error and stats.matched > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
