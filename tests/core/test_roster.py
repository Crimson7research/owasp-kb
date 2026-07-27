import pytest

from owasp_kb.core.roster import (
    Finding,
    RosterError,
    build_roster,
    dedupe_findings,
    resolve_exemption,
    resolve_finding,
)


def _finding(req_id, chapter, section, file="src/auth.py", line=42, cwe="CWE-306"):
    return Finding(
        req_id=req_id,
        chapter=chapter,
        section=section,
        verdict="GAP",
        evidence="no check",
        file=file,
        line=line,
        cwe=cwe,
        remediation=None,
        trace=None,
    )


def test_findings_at_the_same_location_merge():
    merged = dedupe_findings(
        [
            _finding("V6.2.1", "V6", "V6.2"),
            _finding("V8.3.1", "V8", "V8.3"),
        ]
    )
    assert len(merged) == 1


def test_merged_finding_keeps_every_requirement_with_its_context():
    """A reader must see one entry covers both chapters; dropping the second
    silently costs a chapter its coverage in the roster."""
    merged = dedupe_findings(
        [
            _finding("V6.2.1", "V6", "V6.2"),
            _finding("V8.3.1", "V8", "V8.3"),
        ]
    )
    covered = merged[0].covers
    assert {c.req_id for c in covered} == {"V6.2.1", "V8.3.1"}
    assert {c.chapter for c in covered} == {"V6", "V8"}
    assert {c.section for c in covered} == {"V6.2", "V8.3"}


def test_different_locations_do_not_merge():
    merged = dedupe_findings(
        [
            _finding("V6.2.1", "V6", "V6.2", line=42),
            _finding("V6.2.2", "V6", "V6.2", line=99),
        ]
    )
    assert len(merged) == 2


def test_different_cwe_at_the_same_location_does_not_merge():
    """Two distinct weaknesses can share a line."""
    merged = dedupe_findings(
        [
            _finding("V6.2.1", "V6", "V6.2", cwe="CWE-306"),
            _finding("V1.2.1", "V1", "V1.2", cwe="CWE-89"),
        ]
    )
    assert len(merged) == 2


def test_findings_without_a_location_never_merge():
    """An INSUFFICIENT EVIDENCE verdict has no file or line; merging those would
    collapse unrelated unknowns into one."""
    a = Finding(
        req_id="V6.2.1",
        chapter="V6",
        section="V6.2",
        verdict="INSUFFICIENT EVIDENCE",
        evidence="could not determine",
        file=None,
        line=None,
        cwe=None,
        remediation=None,
        trace=None,
    )
    b = Finding(
        req_id="V8.3.1",
        chapter="V8",
        section="V8.3",
        verdict="INSUFFICIENT EVIDENCE",
        evidence="could not determine",
        file=None,
        line=None,
        cwe=None,
        remediation=None,
        trace=None,
    )
    assert len(dedupe_findings([a, b])) == 2


def test_dedupe_preserves_order_of_first_appearance():
    merged = dedupe_findings(
        [
            _finding("V8.3.1", "V8", "V8.3", line=99),
            _finding("V6.2.1", "V6", "V6.2", line=42),
        ]
    )
    assert [m.file_line for m in merged] == ["src/auth.py:99", "src/auth.py:42"]


def test_empty_input_is_empty_output():
    assert dedupe_findings([]) == []


def test_a_refuted_exemption_returns_the_chapter_to_scope():
    assert resolve_exemption(["exemption_refuted"]) == "REFUTED"


def test_one_refutation_outweighs_a_confirmation():
    """Finding the exempted construct is positive evidence; failing to find it
    is not."""
    assert resolve_exemption(["exemption_holds", "exemption_refuted"]) == "REFUTED"


def test_a_held_exemption_is_verified():
    assert resolve_exemption(["exemption_holds"]) == "N/A (verified)"


def test_a_single_unclear_escalates():
    assert resolve_exemption(["unclear"]) == "ESCALATE"


def test_unclear_twice_is_unverified_not_justified():
    assert resolve_exemption(["unclear", "unclear"]) == "N/A (unverified)"


def test_unclear_then_held_is_verified():
    assert resolve_exemption(["unclear", "exemption_holds"]) == "N/A (verified)"


def test_no_verdicts_escalates():
    """A refuter that errored must not be read as agreement."""
    assert resolve_exemption([]) == "ESCALATE"


def test_a_confirmed_finding_is_a_gap():
    assert resolve_finding(["confirmed"]) == "GAP"


def test_a_refuted_finding_is_dropped():
    assert resolve_finding(["refuted"]) == "DROPPED"


def test_finding_unclear_once_escalates():
    assert resolve_finding(["unclear"]) == "ESCALATE"


def test_finding_unclear_twice_is_unconfirmed():
    assert resolve_finding(["unclear", "unclear"]) == "GAP (unconfirmed)"


def test_a_refutation_beats_a_confirmation_for_findings():
    """A false positive in a client deliverable costs more than a false
    negative, which is recoverable."""
    assert resolve_finding(["confirmed", "refuted"]) == "DROPPED"


def _f(req_id, chapter, section, verdict="GAP", **kw):
    return Finding(
        req_id=req_id, chapter=chapter, section=section, verdict=verdict, evidence="e", **kw
    )


REQS = [
    {"req_id": "V6.2.1", "chapter": "V6", "section": "V6.2", "level": "1"},
    {"req_id": "V6.2.2", "chapter": "V6", "section": "V6.2", "level": "2"},
    {"req_id": "V7.1.1", "chapter": "V7", "section": "V7.1", "level": "2"},
]


def test_every_requirement_appears_exactly_once():
    roster = build_roster(
        requirements=REQS,
        findings=[_f("V6.2.1", "V6", "V6.2", file="a.py", line=1, cwe="CWE-1", trace="t")],
        chapter_states={"V6": "APPLIES", "V7": "N/A (verified)"},
        detail=True,
    )
    assert roster["count"] == 3
    assert len(roster["entries"]) == 3
    assert roster["complete"] is True


def test_a_requirement_with_no_verdict_is_insufficient_evidence():
    """Absence of a result is not absence of a problem."""
    roster = build_roster(
        requirements=REQS,
        findings=[],
        chapter_states={"V6": "APPLIES", "V7": "APPLIES"},
        detail=True,
    )
    assert {e["verdict"] for e in roster["entries"]} == {"INSUFFICIENT EVIDENCE"}


def test_requirements_in_an_exempt_chapter_inherit_the_chapter_state():
    roster = build_roster(
        requirements=REQS,
        findings=[],
        chapter_states={"V6": "APPLIES", "V7": "N/A (verified)"},
        detail=True,
    )
    by_id = {e["req_id"]: e for e in roster["entries"]}
    assert by_id["V7.1.1"]["verdict"] == "N/A (verified)"


def test_an_unverified_exemption_is_distinguishable_in_the_roster():
    roster = build_roster(
        requirements=REQS, findings=[], chapter_states={"V6": "APPLIES", "V7": "N/A (unverified)"}
    )
    by_id = {e["req_id"]: e for e in roster["needs_attention"]}
    assert by_id["V7.1.1"]["verdict"] == "N/A (unverified)"
    assert roster["counts"]["N/A (unverified)"] == 1


def test_counts_sum_to_the_total():
    roster = build_roster(
        requirements=REQS,
        findings=[_f("V6.2.1", "V6", "V6.2", file="a.py", line=1, cwe="CWE-1", trace="t")],
        chapter_states={"V6": "APPLIES", "V7": "N/A (verified)"},
    )
    assert sum(roster["counts"].values()) == roster["count"]


def test_a_verdict_for_an_unknown_requirement_is_an_error():
    """A finding citing a requirement not in scope means the scope and the
    findings disagree, which must not be silently reconciled."""
    with pytest.raises(RosterError, match="V99.9.9"):
        build_roster(
            requirements=REQS,
            findings=[_f("V99.9.9", "V99", "V99.9", file="a.py", line=1, cwe="CWE-1")],
            chapter_states={"V6": "APPLIES", "V7": "APPLIES"},
        )


def test_a_chapter_with_no_state_is_an_error():
    with pytest.raises(RosterError, match="V7"):
        build_roster(requirements=REQS, findings=[], chapter_states={"V6": "APPLIES"})


def test_an_unknown_verdict_is_an_error():
    with pytest.raises(RosterError, match="NOT A VERDICT"):
        build_roster(
            requirements=REQS,
            findings=[
                _f(
                    "V6.2.1",
                    "V6",
                    "V6.2",
                    verdict="NOT A VERDICT",
                    file="a.py",
                    line=1,
                    cwe="CWE-1",
                )
            ],
            chapter_states={"V6": "APPLIES", "V7": "APPLIES"},
        )


def test_a_merged_finding_marks_all_its_requirements():
    """Dedup must not cost the second requirement its verdict."""
    roster = build_roster(
        requirements=REQS,
        findings=[
            _f("V6.2.1", "V6", "V6.2", file="a.py", line=1, cwe="CWE-1", trace="t"),
            _f("V6.2.2", "V6", "V6.2", file="a.py", line=1, cwe="CWE-1", trace="t"),
        ],
        chapter_states={"V6": "APPLIES", "V7": "N/A (verified)"},
        detail=True,
    )
    by_id = {e["req_id"]: e for e in roster["entries"]}
    assert by_id["V6.2.1"]["verdict"] == "GAP"
    assert by_id["V6.2.2"]["verdict"] == "GAP"
    assert by_id["V6.2.1"]["finding_id"] == by_id["V6.2.2"]["finding_id"]


# -- require_verification (#15) ------------------------------------------


def test_a_gap_without_a_verifier_trace_is_rejected():
    """172 findings shipped unverified in the first real run because the skill
    asked for a verifier and nothing required its result. A GAP with no trace
    now cannot form a roster at all."""
    with pytest.raises(RosterError, match="verifier"):
        build_roster(
            requirements=REQS,
            findings=[_f("V6.2.1", "V6", "V6.2", verdict="GAP", file="a.py", line=1, cwe="CWE-1")],
            chapter_states={"V6": "APPLIES", "V7": "N/A (verified)"},
        )


def test_the_rejection_names_the_requirements_and_the_way_out():
    with pytest.raises(RosterError) as excinfo:
        build_roster(
            requirements=REQS,
            findings=[_f("V6.2.1", "V6", "V6.2", verdict="GAP", file="a.py", line=1, cwe="CWE-1")],
            chapter_states={"V6": "APPLIES", "V7": "N/A (verified)"},
        )
    message = str(excinfo.value)
    assert "V6.2.1" in message
    assert "owasp-finding-verifier" in message
    assert "GAP (unconfirmed)" in message


def test_a_gap_with_a_trace_is_accepted():
    roster = build_roster(
        requirements=REQS,
        findings=[
            _f(
                "V6.2.1",
                "V6",
                "V6.2",
                verdict="GAP",
                file="a.py",
                line=1,
                cwe="CWE-1",
                trace="untrusted input at a.py:1 reaches exec",
            )
        ],
        chapter_states={"V6": "APPLIES", "V7": "N/A (verified)"},
    )
    assert roster["counts"]["GAP"] == 1


def test_gap_unconfirmed_needs_no_trace():
    """An honestly-downgraded finding is the deliberate way out; requiring a
    trace there would make the escape hatch unusable."""
    roster = build_roster(
        requirements=REQS,
        findings=[
            _f(
                "V6.2.1",
                "V6",
                "V6.2",
                verdict="GAP (unconfirmed)",
                file="a.py",
                line=1,
                cwe="CWE-1",
            )
        ],
        chapter_states={"V6": "APPLIES", "V7": "N/A (verified)"},
    )
    assert roster["counts"]["GAP (unconfirmed)"] == 1


def test_other_verdicts_need_no_trace():
    roster = build_roster(
        requirements=REQS,
        findings=[_f("V6.2.1", "V6", "V6.2", verdict="MET", file="a.py", line=1, cwe=None)],
        chapter_states={"V6": "APPLIES", "V7": "N/A (verified)"},
    )
    assert roster["counts"]["MET"] == 1


def test_verification_can_be_waived_explicitly():
    """A deliberately quick pass stays possible, but never by default."""
    roster = build_roster(
        requirements=REQS,
        findings=[_f("V6.2.1", "V6", "V6.2", verdict="GAP", file="a.py", line=1, cwe="CWE-1")],
        chapter_states={"V6": "APPLIES", "V7": "N/A (verified)"},
        require_verification=False,
    )
    assert roster["counts"]["GAP"] == 1


# -- response size (#14) --------------------------------------------------


def test_roster_response_stays_within_a_usable_size():
    """The tool enforcing completeness must return something a caller can read.
    Measured at 105,041 characters on a 253-requirement, 172-finding roster."""
    import json

    requirements = [
        {"req_id": f"V{c}.1.{i}", "chapter": f"V{c}", "section": f"V{c}.1", "level": "2"}
        for c in range(1, 18)
        for i in range(1, 16)
    ]
    findings = [
        Finding(
            req_id=r["req_id"],
            chapter=r["chapter"],
            section=r["section"],
            verdict="GAP",
            evidence="e" * 80,
            file=f"src/f{i}.c",
            line=i,
            cwe="CWE-306",
            trace="t" * 120,
            remediation="Authentication_Cheat_Sheet#password-storage",
        )
        for i, r in enumerate(requirements[:172])
    ]
    roster = build_roster(
        requirements=requirements,
        findings=findings,
        chapter_states={f"V{c}": "APPLIES" for c in range(1, 18)},
    )
    assert len(json.dumps(roster)) < 40_000


def test_roster_does_not_echo_back_the_evidence_it_was_given():
    """The caller supplied evidence, trace and remediation; returning them is
    72% of the payload and pure redundancy."""
    import json

    roster = build_roster(
        requirements=REQS,
        findings=[
            _f(
                "V6.2.1",
                "V6",
                "V6.2",
                verdict="GAP",
                file="a.py",
                line=1,
                cwe="CWE-1",
                trace="a very distinctive trace string",
                remediation="Some_Cheat_Sheet#anchor",
            )
        ],
        chapter_states={"V6": "APPLIES", "V7": "N/A (verified)"},
    )
    blob = json.dumps(roster)
    assert "a very distinctive trace string" not in blob
    assert "Some_Cheat_Sheet#anchor" not in blob


def test_roster_reports_findings_by_identity_and_resolution():
    roster = build_roster(
        requirements=REQS,
        findings=[
            _f("V6.2.1", "V6", "V6.2", verdict="GAP", file="a.py", line=1, cwe="CWE-1", trace="t")
        ],
        chapter_states={"V6": "APPLIES", "V7": "N/A (verified)"},
    )
    finding = roster["findings"][0]
    assert finding["id"] == 0
    assert finding["verdict"] == "GAP"
    assert finding["location"] == "a.py:1"
    assert finding["covers"] == ["V6.2.1"]


def test_roster_surfaces_only_the_entries_needing_attention():
    roster = build_roster(
        requirements=REQS,
        findings=[],
        chapter_states={"V6": "APPLIES", "V7": "N/A (verified)"},
    )
    assert "entries" not in roster
    attention = {e["req_id"] for e in roster["needs_attention"]}
    assert attention == {"V6.2.1", "V6.2.2"}  # the two INSUFFICIENT EVIDENCE ones


def test_roster_reports_counts_per_chapter():
    roster = build_roster(
        requirements=REQS,
        findings=[],
        chapter_states={"V6": "APPLIES", "V7": "N/A (verified)"},
    )
    assert roster["by_chapter"]["V7"] == {"N/A (verified)": 1}


def test_detail_returns_the_full_entry_list():
    roster = build_roster(
        requirements=REQS,
        findings=[],
        chapter_states={"V6": "APPLIES", "V7": "N/A (verified)"},
        detail=True,
    )
    assert len(roster["entries"]) == 3


def test_a_waived_roster_declares_that_it_was_waived():
    """'GAP (unconfirmed)' announces itself via needs_attention. A boolean flag
    would not, so a waived roster would look identical to a verified one."""
    roster = build_roster(
        requirements=REQS,
        findings=[_f("V6.2.1", "V6", "V6.2", verdict="GAP", file="a.py", line=1, cwe="CWE-1")],
        chapter_states={"V6": "APPLIES", "V7": "N/A (verified)"},
        require_verification=False,
    )
    assert roster["verification_required"] is False


def test_a_normal_roster_declares_verification_was_required():
    roster = build_roster(
        requirements=REQS,
        findings=[],
        chapter_states={"V6": "APPLIES", "V7": "N/A (verified)"},
    )
    assert roster["verification_required"] is True
