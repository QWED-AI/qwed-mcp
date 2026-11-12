"""Process cleanup in tools.py: a failed kill or wait is logged, not
silently dropped (QWED_RULES Principle 6, "failures must remain visible")."""

import asyncio
import logging

import pytest

from qwed_mcp import tools

LOGGER = "qwed-mcp.tools"


class _FakeTransport:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class _FakeStream:
    def __init__(self):
        self._transport = _FakeTransport()


class _FakeProc:
    def __init__(self, kill_error=None):
        self.pid = 12345
        self.kill_error = kill_error
        self.stdout = _FakeStream()
        self.stderr = _FakeStream()
        self.stdin = _FakeStream()

    def kill(self):
        if self.kill_error is not None:
            raise self.kill_error

    async def wait(self):
        await asyncio.sleep(3600)


def test_close_streams_closes_all_three_streams():
    proc = _FakeProc()
    tools._close_streams(proc)
    assert proc.stdout._transport.closed
    assert proc.stderr._transport.closed
    assert proc.stdin._transport.closed


def test_close_streams_skips_a_missing_stream():
    proc = _FakeProc()
    proc.stdin = None
    tools._close_streams(proc)
    assert proc.stdout._transport.closed


def test_failed_kill_after_output_cap_is_logged(caplog):
    caplog.set_level(logging.DEBUG, logger=LOGGER)
    tools._handle_cap_exceeded(_FakeProc(kill_error=OSError("denied")))
    assert any("kill" in r.getMessage().lower() for r in caplog.records)


@pytest.mark.asyncio
async def test_failed_kill_and_wait_on_windows_are_logged(caplog, monkeypatch):
    caplog.set_level(logging.DEBUG, logger=LOGGER)
    monkeypatch.setattr(tools.sys, "platform", "win32")
    await tools._kill_process(_FakeProc(kill_error=OSError("denied")))
    messages = [r.getMessage().lower() for r in caplog.records]
    assert any("kill" in m for m in messages)
    assert any("exit" in m or "wait" in m for m in messages)


@pytest.mark.asyncio
async def test_fallback_kill_of_a_finished_process_is_logged(caplog, monkeypatch):
    caplog.set_level(logging.DEBUG, logger=LOGGER)
    monkeypatch.setattr(tools.sys, "platform", "linux")

    def no_group(pid):
        raise RuntimeError("no process group")

    monkeypatch.setattr(tools.os, "getpgid", no_group, raising=False)
    await tools._kill_process(_FakeProc(kill_error=ProcessLookupError()))
    messages = [r.getMessage().lower() for r in caplog.records]
    assert any("already" in m for m in messages)
