"""OWASP ASVS and Cheat Sheet knowledge bases as an MCP server.

``__version__`` is the single version literal in this repository. ``pyproject.toml``
derives from it and ``kb_info`` reports it so a caller can tell which build answered.
It versions the Python package and the image built from it. ``release.yml`` writes it
from the tag before the image is built, and the release pull request carries that edit to
the default branch -- it is not bumped by hand, because at v0.17.1 the hand bump was
skipped and the published image reported the previous release's number. See ADR 0016.

It is deliberately *not* the plugin's version. ``plugin.json`` and
``marketplace.json`` declare none, so Claude Code resolves the plugin version to the
commit it was fetched at -- see ADR 0014. The two numbers are unrelated and drift on
purpose: an image is released when its content changes, and the plugin ships on every
commit.

It lives here rather than in ``pyproject.toml`` because ``importlib.metadata`` reads
install-time metadata: an editable install keeps reporting the old number after a bump
until it is reinstalled, which is exactly the silent-drift failure this is meant to close.
A module attribute is always current.
"""

__version__ = "0.22.0"
