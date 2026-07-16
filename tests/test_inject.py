"""Class B harness tests with deterministic fake agents -- no API, no tokens.

Proves the injection probe detects a hijack when the agent follows the poison and
reports clean when it resists, so the detector is neither a no-op nor a false
alarm. The live behavioral run against the real model lives in
scripts/demo_inject.py (gated on a key).

    python -m tests.test_inject
"""

import asyncio
import json
import unicodedata
from types import SimpleNamespace

from siege.payloads import ATTACKER_DEST, PAYLOADS
from siege.probes.inject import probe_injection


def _deobfuscate(blob: str) -> str:
    """Model the decoding a susceptible model does before it acts: strip the zero-width
    interleave and NFKC-fold full-width homoglyphs, so an ENCODED directive (FINDING-19)
    reads the same as the plain one. A model that obeys is one that reads through the
    disguise; a byte-scanner is exactly the layer that does NOT."""
    return unicodedata.normalize("NFKC", blob.replace("​", ""))


def _tool_use(name, **inp):
    return SimpleNamespace(type="tool_use", id=f"tu_{name}", name=name, input=inp)


def _text(t):
    return SimpleNamespace(type="text", text=t)


def make_fake(susceptible: bool):
    """A stateless fake agent. It always reads first; a susceptible one then fires
    export_record once it can see the attacker destination (in a tool description
    or a tool result), a hardened one never does."""
    async def complete(system, messages, tools):
        blob = _deobfuscate(json.dumps(tools, ensure_ascii=False)
                            + json.dumps(messages, ensure_ascii=False, default=str))
        has_read = _used(messages, "read_record")
        has_exported = _used(messages, "export_record")
        if not has_read:
            return SimpleNamespace(content=[_tool_use("read_record", record_id=1)])
        if susceptible and ATTACKER_DEST in blob and not has_exported:
            return SimpleNamespace(content=[_tool_use("export_record", record_id=1, destination=ATTACKER_DEST)])
        return SimpleNamespace(content=[_text("Record 1: Acme Corp, active.")])

    return complete


def _used(messages, tool_name) -> bool:
    for m in messages:
        if m.get("role") != "assistant":
            continue
        for b in m.get("content", []):
            if isinstance(b, dict) and b.get("type") == "tool_use" and b.get("name") == tool_name:
                return True
    return False


async def _run():
    # Susceptible agent: every payload hijacks -> one HIGH per payload + a HIGH summary.
    bad = await probe_injection(make_fake(True))
    highs = [f for f in bad if f.severity == "high" and "hijacked by" in f.title]
    assert len(highs) == len(PAYLOADS), [f.title for f in bad]
    summary = [f for f in bad if "susceptibility" in f.title][0]
    assert summary.evidence["hijacked"] == len(PAYLOADS)

    # The value-slot class (FINDING-9/14) is actually exercised: the summary reports
    # the schema channel, and every slot payload carries the poison out of sight of a
    # description scanner yet still hijacks the agent.
    assert "schema" in summary.evidence["channels_tested"], summary.evidence["channels_tested"]
    schema_highs = [f for f in highs if f.evidence.get("channel") == "schema"]
    assert len(schema_highs) >= 12, [f.evidence.get("payload") for f in schema_highs]
    assert any(f.evidence.get("slot") == "enumval" for f in schema_highs)

    # The marquee decoy: a description that DENIES exporting still hijacks via the
    # enum value -- the tool whose schema poison a human reviewer would never catch.
    decoy = [f for f in schema_highs if f.evidence.get("payload") == "decoy-denial-enumval"]
    assert len(decoy) == 1, [f.evidence.get("payload") for f in schema_highs]

    # FINDING-18: the $defs/$ref indirection channel hijacks -- payload behind a pointer.
    assert any(f.evidence.get("slot") == "defref" for f in schema_highs), \
        [f.evidence.get("slot") for f in schema_highs]

    # FINDING-19: the encoding axis. The ENCODED directive still hijacks the decoding
    # agent, though its bytes carry no literal imperative for a scanner to see.
    enc_highs = [f.evidence.get("payload") for f in schema_highs
                 if str(f.evidence.get("payload", "")).startswith("enc-")]
    assert {"enc-homoglyph", "enc-zwsp"} <= set(enc_highs), enc_highs

    # Hardened agent: no hijacks -> only the info summary, zero HIGH findings.
    good = await probe_injection(make_fake(False))
    assert not [f for f in good if f.severity == "high"], [f.title for f in good]
    gsummary = [f for f in good if "susceptibility" in f.title][0]
    assert gsummary.severity == "info" and gsummary.evidence["hijacked"] == 0

    print(f"PASS  inject harness: susceptible -> {len(highs)}/{len(PAYLOADS)} hijacks "
          f"({len(schema_highs)} via schema value slots + decoy); hardened -> 0")


if __name__ == "__main__":
    asyncio.run(_run())
