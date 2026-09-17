"""The enforcement boundary as a machine-checked property.

This is the most concrete evidence the project produces. It converts "the model
holds no authority" from an architectural intention into something that fails
loudly the moment anyone breaks it. Put it in the report.
"""
import ast
import pathlib

import pytest

FORBIDDEN_PREFIXES = (
    "telemail.gmail.adapter",     # the mailbox client
    "telemail.broker",            # the gate itself
    "googleapiclient",            # the Google SDK, by any route
    "google.oauth2",
    "google_auth_oauthlib",
)

# Everything that reads or reasons about attacker-controlled content.
UNTRUSTED_PACKAGES = ["telemail/triage"]


def imports_of(path: pathlib.Path):
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            yield from (a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            yield node.module


def untrusted_sources():
    for pkg in UNTRUSTED_PACKAGES:
        yield from sorted(pathlib.Path(pkg).rglob("*.py"))


@pytest.mark.parametrize("path", list(untrusted_sources()),
                         ids=lambda p: str(p))
def test_untrusted_zone_cannot_reach_the_mailbox(path):
    for module in imports_of(path):
        assert not module.startswith(FORBIDDEN_PREFIXES), (
            f"{path} imports {module} — the enforcement boundary is broken")


def test_the_untrusted_zone_is_not_empty():
    """Guards against the test passing because it scanned nothing."""
    assert len(list(untrusted_sources())) >= 2


def test_dispatch_is_static_never_getattr():
    """`getattr(adapter, intent.op)` would turn a string from a model into a
    method name. Assert the broker never does it."""
    src = pathlib.Path("telemail/broker/broker.py").read_text()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id != "getattr", "broker uses getattr for dispatch"


# Modules permitted to reference the mailbox client. Every one is in the
# deterministic zone and none of them reasons about attacker-controlled content.
# Adding a name here is a deliberate widening of the trusted computing base and
# should be argued for, not done to make a test pass.
PERMITTED_ADAPTER_HOLDERS = {
    "telemail/gmail/adapter.py",   # is the client
    "telemail/gmail/auth.py",      # builds its credentials
    "telemail/sync.py",            # drives it; is handed one by the caller
    "telemail/__main__.py",        # the composition root; assembles, decides nothing
}


def test_adapter_holders_are_an_explicit_allowlist():
    """Complete mediation: the set of modules that can reach the mailbox is
    small, enumerated, and entirely inside the deterministic zone."""
    holders = set()
    for path in sorted(pathlib.Path("telemail").rglob("*.py")):
        for module in imports_of(path):
            if module.startswith(("telemail.gmail.adapter", "googleapiclient")):
                holders.add(str(path))
    unexpected = holders - PERMITTED_ADAPTER_HOLDERS
    assert not unexpected, f"mailbox client newly reachable from: {sorted(unexpected)}"


def test_no_adapter_holder_is_in_the_untrusted_zone():
    """The allowlist above must never grow to include something that reads
    attacker-authored content."""
    for holder in PERMITTED_ADAPTER_HOLDERS:
        assert not any(holder.startswith(pkg) for pkg in UNTRUSTED_PACKAGES), holder
