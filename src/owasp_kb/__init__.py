"""OWASP ASVS and Cheat Sheet knowledge bases as an MCP server.

``__version__`` is the single version literal in this repository. ``pyproject.toml``
derives from it, ``plugin.json`` and ``marketplace.json`` are asserted equal to it, and
``kb_info`` reports it so a caller can tell which build answered.

It lives here rather than in ``pyproject.toml`` because ``importlib.metadata`` reads
install-time metadata: an editable install keeps reporting the old number after a bump
until it is reinstalled, which is exactly the silent-drift failure this is meant to close.
A module attribute is always current.
"""

__version__ = "0.10.0"
