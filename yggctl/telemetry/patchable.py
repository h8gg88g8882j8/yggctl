"""Forward attribute access to the package namespace for monkeypatch tests."""

import importlib


class _API:
    __slots__ = ()

    def __getattr__(self, name: str):
        return getattr(importlib.import_module("telemetry"), name)


API = _API()
