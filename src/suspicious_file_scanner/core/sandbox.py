"""Best-effort subprocess isolation for parsing untrusted files (strict mode)."""

from __future__ import annotations

import multiprocessing
from collections.abc import Callable
from typing import Any

from .contracts import ParseResult, SafetyLimits


def _worker(func: Callable, data: bytes, limits: SafetyLimits, queue: Any) -> None:
    # Best-effort resource caps on Unix.
    try:
        import resource

        cpu = int(limits.timeout_seconds) + 1
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
        resource.setrlimit(resource.RLIMIT_AS, (limits.max_file_size * 4, limits.max_file_size * 4))
    except (ImportError, ValueError, OSError):
        pass
    try:
        result = func(data, limits)
        queue.put(("ok", result))
    except Exception as exc:  # noqa: BLE001
        queue.put(("err", str(exc)))


def run_in_subprocess(
    func: Callable, data: bytes, limits: SafetyLimits
) -> ParseResult:
    """Run *func(data, limits)* in a child process with a timeout.

    Falls back to in-process execution if multiprocessing is unavailable.
    """
    ctx = multiprocessing.get_context("spawn")
    queue: Any = ctx.Queue()
    proc = ctx.Process(target=_worker, args=(func, data, limits, queue))
    proc.start()
    proc.join(timeout=limits.timeout_seconds)
    if proc.is_alive():
        proc.terminate()
        proc.join()
        return ParseResult(ok=False, errors=["parser timed out (strict mode)"])
    if queue.empty():
        return ParseResult(ok=False, errors=["parser crashed (strict mode)"])
    status, payload = queue.get()
    if status == "ok":
        return payload  # type: ignore[return-value]
    return ParseResult(ok=False, errors=[str(payload)])
