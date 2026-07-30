import json

import pytest

from owasp_kb.core.roster import (
    CLAIMS_NEEDING_AN_ADVERSARY,
    VERDICTS,
    Finding,
    RosterError,
    build_roster,
    dedupe_findings,
    load_session_findings,
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


def test_a_met_and_a_gap_at_the_same_location_do_not_merge():
    """Two requirements can legitimately resolve differently at one line -- one
    met, one gapped, both anchored to the same doc line. Merging kept whichever
    verdict arrived first and discarded the other, so a real GAP was counted as
    MET and the failure count came out short. Under-reporting failures is the
    worst available direction for this tool."""
    met = Finding(**{**vars(_finding("V2.1.1", "V2", "V2.1", cwe=None)), "verdict": "MET"})
    gap = _finding("V2.1.3", "V2", "V2.1", cwe=None)
    out = dedupe_findings([met, gap])
    assert len(out) == 2, "the GAP was absorbed into the MET"
    assert {f.verdict for f in out} == {"MET", "GAP"}


def test_merging_does_not_depend_on_the_order_findings_arrive_in():
    """Whichever verdict arrived first used to win, so the same set of findings
    produced a different pass/fail count depending on dispatch order."""
    met = Finding(**{**vars(_finding("V2.1.1", "V2", "V2.1", cwe=None)), "verdict": "MET"})
    gap = _finding("V2.1.3", "V2", "V2.1", cwe=None)
    forward = sorted(f.verdict for f in dedupe_findings([met, gap]))
    reverse = sorted(f.verdict for f in dedupe_findings([gap, met]))
    assert forward == reverse == ["GAP", "MET"]


def test_same_verdict_at_the_same_location_still_merges():
    """The merge is what stops one defect reading as four independent problems.
    Narrowing it to same-verdict must not disable it."""
    merged = dedupe_findings(
        [
            _finding("V6.2.1", "V6", "V6.2", cwe=None),
            _finding("V8.3.1", "V8", "V8.3", cwe=None),
        ]
    )
    assert len(merged) == 1
    assert {c.req_id for c in merged[0].covers} == {"V6.2.1", "V8.3.1"}


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


def test_a_refuted_finding_is_insufficient_evidence_gap_refuted():
    """A refutation disproves the reported defect; it does not establish the
    control is adequate, so it resolves to `INSUFFICIENT EVIDENCE (gap
    refuted)` -- not a dropped line and not `MET`."""
    assert resolve_finding(["refuted"]) == "INSUFFICIENT EVIDENCE (gap refuted)"


def test_finding_unclear_once_escalates():
    assert resolve_finding(["unclear"]) == "ESCALATE"


def test_finding_unclear_twice_is_unconfirmed():
    assert resolve_finding(["unclear", "unclear"]) == "GAP (unconfirmed)"


def test_a_refutation_beats_a_confirmation_for_findings():
    """A false positive in a client deliverable costs more than a false
    negative, which is recoverable."""
    assert resolve_finding(["confirmed", "refuted"]) == "INSUFFICIENT EVIDENCE (gap refuted)"


def _f(req_id, chapter, section, verdict="GAP", **kw):
    kw.setdefault("evidence", "e")
    return Finding(req_id=req_id, chapter=chapter, section=section, verdict=verdict, **kw)


PRIOR = "docs/security/asvs-5.0.0-l2-firmware.md"


@pytest.mark.parametrize("field", ["evidence", "trace", "remediation"])
def test_an_excluded_path_is_caught_in_any_cited_field(field):
    """Citing it in prose is the same contamination as citing it as the location."""
    kwargs = {"file": "a.py", "line": 1, "cwe": "CWE-1", "trace": "t"}
    kwargs[field] = f"as recorded in {PRIOR}"
    with pytest.raises(RosterError, match="excluded"):
        build_roster(
            requirements=REQS,
            findings=[_f("V6.2.1", "V6", "V6.2", **kwargs)],
            chapter_states={"V6": "APPLIES", "V7": "N/A (verified)"},
            excluded=[PRIOR],
        )


def test_an_insufficient_evidence_finding_may_name_the_excluded_path():
    """The prompts tell an agent to say when a verdict would depend on excluded
    material. A verdict that concludes nothing cannot import a conclusion, and
    rejecting it punishes the honest answer."""
    roster = build_roster(
        requirements=REQS,
        findings=[
            _f(
                "V6.2.1",
                "V6",
                "V6.2",
                verdict="INSUFFICIENT EVIDENCE",
                evidence=f"a verdict here would depend on {PRIOR}, which was not opened",
            )
        ],
        chapter_states={"V6": "APPLIES", "V7": "N/A (verified)"},
        excluded=[PRIOR],
    )
    assert roster["counts"]["INSUFFICIENT EVIDENCE"] >= 1


def test_an_asserting_verdict_still_cannot_cite_the_excluded_path():
    """The exemption is narrow. A GAP or a verified N/A asserts something a prior
    report could have supplied, so it stays in scope."""
    with pytest.raises(RosterError, match="excluded"):
        build_roster(
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
                    trace=f"confirmed against {PRIOR}",
                )
            ],
            chapter_states={"V6": "APPLIES", "V7": "N/A (verified)"},
            excluded=[PRIOR],
        )


def test_the_exclusion_error_names_the_path_and_the_way_out():
    """A prior report in the target repo is someone else's conclusion. The
    verifiers that found one caught themselves by disposition; this is the
    control that does not rely on disposition -- and the message it raises
    must name both the path and the requirement, and point at the way out."""
    with pytest.raises(RosterError) as excinfo:
        build_roster(
            requirements=REQS,
            findings=[_f("V6.2.1", "V6", "V6.2", file=PRIOR, line=413, cwe="CWE-1", trace="t")],
            chapter_states={"V6": "APPLIES", "V7": "N/A (verified)"},
            excluded=[PRIOR],
        )
    message = str(excinfo.value)
    assert PRIOR in message
    assert "V6.2.1" in message
    assert "re-derive" in message.lower()


def test_an_empty_exclusion_list_changes_nothing():
    """The default path must be untouched -- most targets have no prior report."""
    roster = build_roster(
        requirements=REQS,
        findings=[_f("V6.2.1", "V6", "V6.2", file="a.py", line=1, cwe="CWE-1", trace="t")],
        chapter_states={"V6": "APPLIES", "V7": "N/A (verified)"},
        excluded=[],
    )
    assert roster["complete"] is True


def test_readable_docs_are_not_caught_by_the_exclusion():
    """docs/ is not excluded wholesale. ASVS documentation-class requirements --
    V7.1.1 is literally 'verify the timeout is documented' -- are unanswerable if
    design docs cannot be cited."""
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
                trace="no timeout stated in docs/ble-app-architecture.md",
            )
        ],
        chapter_states={"V6": "APPLIES", "V7": "N/A (verified)"},
        excluded=[PRIOR],
    )
    assert roster["counts"]["GAP"] == 1


def test_the_exclusion_error_truncates_after_three_requirements():
    """One contaminated finding routinely covers several requirements. The
    message names a few and counts the rest; nothing currently checks either."""
    reqs = [
        {"req_id": f"V6.2.{i}", "chapter": "V6", "section": "V6.2", "level": "1"}
        for i in range(1, 6)
    ]
    findings = [
        _f(f"V6.2.{i}", "V6", "V6.2", file=PRIOR, line=i, cwe="CWE-1", trace="t")
        for i in range(1, 6)
    ]
    with pytest.raises(RosterError) as excinfo:
        build_roster(
            requirements=reqs,
            findings=findings,
            chapter_states={"V6": "APPLIES"},
            excluded=[PRIOR],
        )
    message = str(excinfo.value)
    assert message.startswith("5 requirement(s)")
    assert message.count(" cites ") == 3
    assert "and 2 more" in message


def test_contamination_is_reported_before_a_missing_trace():
    """Both are wrong, but re-deriving from source is the first move; being told
    to dispatch a verifier for a finding you must discard wastes the dispatch."""
    with pytest.raises(RosterError, match="excluded"):
        build_roster(
            requirements=REQS,
            findings=[_f("V6.2.1", "V6", "V6.2", file=PRIOR, line=413, cwe="CWE-1")],
            chapter_states={"V6": "APPLIES", "V7": "N/A (verified)"},
            excluded=[PRIOR],
        )


def test_a_bare_string_for_excluded_is_rejected():
    """A string is iterable character by character, so 'docs/x.md' would match
    almost anything -- exactly the footgun a single prior report invites."""
    with pytest.raises(RosterError) as excinfo:
        build_roster(
            requirements=REQS,
            findings=[_f("V6.2.1", "V6", "V6.2", file="a.py", line=1, cwe="CWE-1", trace="t")],
            chapter_states={"V6": "APPLIES", "V7": "N/A (verified)"},
            excluded=PRIOR,
        )
    assert f"['{PRIOR}']" in str(excinfo.value)


def test_a_non_string_entry_in_excluded_is_rejected():
    with pytest.raises(RosterError, match="non-path"):
        build_roster(
            requirements=REQS,
            findings=[_f("V6.2.1", "V6", "V6.2", file="a.py", line=1, cwe="CWE-1", trace="t")],
            chapter_states={"V6": "APPLIES", "V7": "N/A (verified)"},
            excluded=[None],
        )


def test_a_blank_entry_in_excluded_behaves_as_no_exclusion():
    """'' is a substring of everything; it must not become exclude-everything."""
    roster = build_roster(
        requirements=REQS,
        findings=[_f("V6.2.1", "V6", "V6.2", file="a.py", line=1, cwe="CWE-1", trace="t")],
        chapter_states={"V6": "APPLIES", "V7": "N/A (verified)"},
        excluded=[""],
    )
    assert roster["complete"] is True


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


# -- N/A (verified) needs a refuter trace (#23) ----------------------------


def test_a_verified_na_without_a_refuter_trace_is_rejected():
    """An N/A is a claim, exactly like a chapter exemption. Twelve V7
    requirements were judged inapplicable with good reasons and had nowhere to
    go; giving them a home must not also give them a free pass."""
    with pytest.raises(RosterError, match="refuter"):
        build_roster(
            requirements=REQS,
            findings=[_f("V6.2.1", "V6", "V6.2", verdict="N/A (verified)")],
            chapter_states={"V6": "APPLIES", "V7": "N/A (verified)"},
        )


def test_the_na_rejection_names_the_requirement_and_the_way_out():
    with pytest.raises(RosterError) as excinfo:
        build_roster(
            requirements=REQS,
            findings=[_f("V6.2.1", "V6", "V6.2", verdict="N/A (verified)")],
            chapter_states={"V6": "APPLIES", "V7": "N/A (verified)"},
        )
    message = str(excinfo.value)
    assert "V6.2.1" in message
    assert "owasp-exemption-refuter" in message
    assert "N/A (unverified)" in message


def test_a_verified_na_with_a_refuter_trace_is_accepted():
    roster = build_roster(
        requirements=REQS,
        findings=[
            _f(
                "V6.2.1",
                "V6",
                "V6.2",
                verdict="N/A (verified)",
                trace="searched for user/account/session constructs; none exist",
            )
        ],
        chapter_states={"V6": "APPLIES", "V7": "N/A (verified)"},
    )
    assert roster["counts"]["N/A (verified)"] == 2  # the finding plus exempt chapter V7


def test_an_unverified_na_needs_no_trace_and_surfaces_for_attention():
    """The honest way past the check. It must stay usable, and it must announce
    itself rather than passing as a checked claim."""
    roster = build_roster(
        requirements=REQS,
        findings=[_f("V6.2.1", "V6", "V6.2", verdict="N/A (unverified)")],
        chapter_states={"V6": "APPLIES", "V7": "N/A (verified)"},
    )
    assert roster["counts"]["N/A (unverified)"] == 1
    assert "V6.2.1" in {e["req_id"] for e in roster["needs_attention"]}


def test_both_claim_types_are_reported_together():
    """A chapter can produce an untraced GAP and an untraced N/A at once. The
    caller should learn about both in one error, not discover the second only
    after fixing the first -- and each requirement must be attributed to the
    adversary that can actually act on it, not lumped under both."""
    with pytest.raises(RosterError) as excinfo:
        build_roster(
            requirements=REQS,
            findings=[
                _f("V6.2.1", "V6", "V6.2", verdict="GAP", file="a.py", line=1, cwe="CWE-1"),
                _f("V6.2.2", "V6", "V6.2", verdict="N/A (verified)"),
            ],
            chapter_states={"V6": "APPLIES", "V7": "N/A (verified)"},
        )
    message = str(excinfo.value)
    verifier_clause = [c for c in message.split(";") if "owasp-finding-verifier" in c][0]
    refuter_clause = [c for c in message.split(";") if "owasp-exemption-refuter" in c][0]
    assert "V6.2.1" in verifier_clause
    assert "V6.2.2" not in verifier_clause
    assert "V6.2.2" in refuter_clause
    assert "V6.2.1" not in refuter_clause


def test_the_count_is_requirements_not_findings_or_roles():
    """dedupe_findings merges findings sharing a location, so one untraced GAP
    routinely covers several requirements. The agent has to act on each of them,
    so that is what the message counts -- not findings, and not adversaries."""
    with pytest.raises(RosterError) as excinfo:
        build_roster(
            requirements=REQS,
            findings=[
                _f("V6.2.1", "V6", "V6.2", verdict="GAP", file="a.py", line=1, cwe="CWE-1"),
                _f("V6.2.2", "V6", "V6.2", verdict="GAP", file="a.py", line=1, cwe="CWE-1"),
            ],
            chapter_states={"V6": "APPLIES", "V7": "N/A (verified)"},
        )
    message = str(excinfo.value)
    assert message.startswith("2 requirement(s)")
    assert "V6.2.1" in message
    assert "V6.2.2" in message


def test_an_empty_trace_is_no_trace():
    """An agent that emits `"trace": ""` rather than omitting the field claims a
    check it never ran. A falsy trace must fail like a missing one, or #15
    returns through a JSON default."""
    with pytest.raises(RosterError, match="owasp-finding-verifier"):
        build_roster(
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
                    trace="",
                )
            ],
            chapter_states={"V6": "APPLIES", "V7": "N/A (verified)"},
        )


def test_every_claim_needing_an_adversary_is_a_real_verdict():
    """A typo in a key switches the rule off silently for that verdict -- an
    instruction with no consumer, again."""
    assert set(CLAIMS_NEEDING_AN_ADVERSARY) <= set(VERDICTS)


def test_na_findings_never_merge_with_each_other():
    """Twelve N/A claims share (file=None, line=None, cwe=None). Merging on that
    would collapse them into a single finding covering all twelve requirements,
    losing every individual reason."""
    merged = dedupe_findings(
        [
            _f("V7.1.2", "V7", "V7.1", verdict="N/A (verified)"),
            _f("V7.2.3", "V7", "V7.2", verdict="N/A (verified)"),
            _f("V7.4.5", "V7", "V7.4", verdict="N/A (verified)"),
        ]
    )
    assert len(merged) == 3
    assert [f.covers[0].req_id for f in merged] == ["V7.1.2", "V7.2.3", "V7.4.5"]


# -- a GAP with no location is rejected; N/A keeps its exemption (#23 spec) --


def test_a_gap_with_no_location_is_rejected():
    """Now that locationless findings are a first-class shape (N/A verdicts have
    no file/line by design), a GAP that lost its location must not slip through
    the same door -- it would reach the report as a verified gap pointing at
    nothing."""
    with pytest.raises(RosterError, match="V6.2.1"):
        build_roster(
            requirements=REQS,
            findings=[_f("V6.2.1", "V6", "V6.2", verdict="GAP", trace="t")],
            chapter_states={"V6": "APPLIES", "V7": "N/A (verified)"},
        )


def test_a_gap_unconfirmed_with_no_location_is_rejected():
    """The self-declaring escape hatch from require_verification does not also
    excuse a missing location."""
    with pytest.raises(RosterError, match="V6.2.1"):
        build_roster(
            requirements=REQS,
            findings=[_f("V6.2.1", "V6", "V6.2", verdict="GAP (unconfirmed)")],
            chapter_states={"V6": "APPLIES", "V7": "N/A (verified)"},
        )


def test_an_na_verified_with_no_location_is_still_accepted():
    """N/A (verified) has no location by design: a requirement that does not
    apply has nowhere to point. The GAP-location check must not catch it too."""
    roster = build_roster(
        requirements=REQS,
        findings=[_f("V6.2.1", "V6", "V6.2", verdict="N/A (verified)", trace="t")],
        chapter_states={"V6": "APPLIES", "V7": "N/A (verified)"},
    )
    assert roster["counts"]["N/A (verified)"] == 2  # the finding plus exempt chapter V7


# -- regression: the V7 run that motivated all of this (#23) ---------------

V7_INAPPLICABLE = [
    ("V7.1.2", "V7.1", "no user account concept exists"),
    ("V7.1.3", "V7.1", "no federated identity or SSO system exists"),
    ("V7.2.1", "V7.2", "no application-level session token exists"),
    ("V7.2.2", "V7.2", "no self-contained or reference token is used"),
    ("V7.2.3", "V7.2", "no reference token exists to evaluate for entropy"),
    ("V7.2.4", "V7.2", "no authentication event exists to trigger regeneration"),
    ("V7.4.2", "V7.4", "no user accounts exist to be disabled or deleted"),
    ("V7.4.3", "V7.4", "no multi-session-per-account model exists"),
    ("V7.4.4", "V7.4", "no authenticated pages exist"),
    ("V7.4.5", "V7.4", "no admin role exists"),
    ("V7.5.2", "V7.5", "no feature to view or terminate other sessions"),
    ("V7.6.1", "V7.6", "no IdP or relying-party relationship exists"),
]


# The 6 applicable requirements the same V7 run found gaps in, each with a
# verifier trace, and the one finder whose reply was cut off short of
# REPORT COMPLETE and had to be recorded as INSUFFICIENT EVIDENCE rather than
# discarded or guessed at.
V7_GAPS = [
    ("V7.1.1", "V7.1", "src/session.c", 88, "CWE-613"),
    ("V7.3.1", "V7.3", "src/session.c", 140, "CWE-384"),
    ("V7.3.2", "V7.3", "src/session.c", 156, "CWE-330"),
    ("V7.4.1", "V7.4", "src/session.c", 201, "CWE-613"),
    ("V7.5.1", "V7.5", "src/session.c", 240, "CWE-306"),
    ("V7.6.2", "V7.6", "src/session.c", 275, "CWE-290"),
]

V7_TRUNCATED = ("V7.2.5", "V7.2")


def test_the_v7_run_resolves_its_inapplicable_requirements():
    """The first end-to-end fan-out recorded the 12 inapplicable requirements as
    INSUFFICIENT EVIDENCE because nothing else could hold them. This is the full
    scenario the spec describes: the same run also confirmed 6 gaps and had one
    finder cut off mid-reply, so both adversary rules -- the refuter's for N/A
    and the verifier's for GAP -- are exercised over one requirement set, and the
    roster must still resolve every requirement and report complete."""
    requirements = (
        [{"req_id": r, "chapter": "V7", "section": s, "level": "2"} for r, s, _ in V7_INAPPLICABLE]
        + [{"req_id": r, "chapter": "V7", "section": s, "level": "2"} for r, s, _, _, _ in V7_GAPS]
        + [{"req_id": V7_TRUNCATED[0], "chapter": "V7", "section": V7_TRUNCATED[1], "level": "2"}]
    )
    na_findings = [
        Finding(
            req_id=req_id,
            chapter="V7",
            section=section,
            verdict="N/A (verified)",
            evidence=reason,
            trace="refuter searched for the construct and could not find it",
        )
        for req_id, section, reason in V7_INAPPLICABLE
    ]
    gap_findings = [
        Finding(
            req_id=req_id,
            chapter="V7",
            section=section,
            verdict="GAP",
            evidence="finder located the gap",
            file=file,
            line=line,
            cwe=cwe,
            trace="verifier confirmed: source-to-sink trace present",
        )
        for req_id, section, file, line, cwe in V7_GAPS
    ]
    truncated_finding = Finding(
        req_id=V7_TRUNCATED[0],
        chapter="V7",
        section=V7_TRUNCATED[1],
        verdict="INSUFFICIENT EVIDENCE",
        evidence="finder's reply did not end with REPORT COMPLETE; discarded and not re-dispatched",
    )
    roster = build_roster(
        requirements=requirements,
        findings=na_findings + gap_findings + [truncated_finding],
        chapter_states={"V7": "APPLIES"},
    )
    assert roster["counts"]["GAP"] == 6
    assert roster["counts"]["N/A (verified)"] == 12
    assert roster["counts"]["INSUFFICIENT EVIDENCE"] == 1
    assert roster["complete"] is True
    assert {e["req_id"] for e in roster["needs_attention"]} == {V7_TRUNCATED[0]}


def test_a_finding_can_carry_a_remediation_quote():
    """A verifier that navigated to a section and read it proves so with a quote.
    build_roster stores it and does not interpret it -- verifying the quote needs
    the index, which lives in the tool adapter, not here."""
    finding = _f(
        "V6.2.1",
        "V6",
        "V6.2",
        verdict="GAP",
        file="a.py",
        line=1,
        cwe="CWE-1",
        trace="t",
        remediation="Authentication_Cheat_Sheet#password-storage",
        remediation_quote="Store passwords with argon2id.",
    )
    assert finding.remediation_quote == "Store passwords with argon2id."


def test_the_roster_does_not_echo_the_remediation_quote():
    """Same reason evidence and trace are not echoed: the caller supplied it, and
    it was 72% of a 109,038-character response when they were."""
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
                trace="t",
                remediation="Authentication_Cheat_Sheet#password-storage",
                remediation_quote="a very distinctive quote string",
            )
        ],
        chapter_states={"V6": "APPLIES", "V7": "N/A (verified)"},
    )
    assert "a very distinctive quote string" not in json.dumps(roster)


def _at_a_py_1(req_id, quote):
    return _f(
        req_id,
        "V6",
        "V6.2",
        verdict="GAP",
        file="a.py",
        line=1,
        cwe="CWE-1",
        trace="t",
        remediation="Authentication_Cheat_Sheet#password-storage",
        remediation_quote=quote,
    )


def test_findings_merge_despite_differing_remediation_quotes():
    """A quote is not identity. Two findings at one (file, line, cwe, verdict) are one
    defect against two requirements however differently each was quoted."""
    roster = build_roster(
        requirements=REQS,
        findings=[_at_a_py_1("V6.2.1", "quote one"), _at_a_py_1("V6.2.2", "quote two")],
        chapter_states={"V6": "APPLIES", "V7": "N/A (verified)"},
    )
    assert len(roster["findings"]) == 1
    assert set(roster["findings"][0]["covers"]) == {"V6.2.1", "V6.2.2"}


# -- session state on disk (#46) --------------------------------------------


def _write_session(tmp_path, session, lines):
    d = tmp_path / "sessions" / session
    d.mkdir(parents=True)
    (d / "findings.jsonl").write_text("\n".join(json.dumps(x) for x in lines) + "\n")
    return tmp_path


def test_findings_load_from_the_session_state_file(tmp_path, monkeypatch):
    """A realistic L2 submission is ~61 KB and evidence alone is 47% of it, so a
    corrected verdict re-sent the whole set. On disk it costs one line."""
    _write_session(tmp_path, "s1", [{"req_id": "V1.1.1", "verdict": "GAP", "evidence": "e"}])
    monkeypatch.setenv("OWASP_KB_STATE", str(tmp_path))
    loaded = load_session_findings("s1")
    assert [f["req_id"] for f in loaded] == ["V1.1.1"]


def test_a_later_line_supersedes_an_earlier_one_for_the_same_requirement(tmp_path, monkeypatch):
    """The correction path: append rather than resubmit. This is the one place
    order carries meaning, and it is amendment history rather than a tie-break --
    once resolved, assembly sees one entry per req_id and stays order-independent,
    which is what #43 established has to hold."""
    _write_session(
        tmp_path,
        "s1",
        [
            {"req_id": "V1.1.1", "verdict": "MET", "evidence": "first"},
            {"req_id": "V2.1.1", "verdict": "GAP", "evidence": "other"},
            {"req_id": "V1.1.1", "verdict": "GAP", "evidence": "corrected"},
        ],
    )
    monkeypatch.setenv("OWASP_KB_STATE", str(tmp_path))
    loaded = {f["req_id"]: f for f in load_session_findings("s1")}
    assert loaded["V1.1.1"]["verdict"] == "GAP"
    assert loaded["V1.1.1"]["evidence"] == "corrected"
    assert loaded["V2.1.1"]["verdict"] == "GAP", "an unrelated finding must survive"


def test_a_missing_session_file_raises_rather_than_reading_as_empty(tmp_path, monkeypatch):
    """An empty set would produce a roster reporting every requirement as
    INSUFFICIENT EVIDENCE, which reads as an assessment result rather than as a
    missing file. Unlike the exclusion hook, this fails closed."""
    monkeypatch.setenv("OWASP_KB_STATE", str(tmp_path))
    with pytest.raises(RosterError, match="no findings for session"):
        load_session_findings("absent")


@pytest.mark.parametrize(
    "bad,match",
    [("{not json", "not valid JSON"), ('{"verdict": "GAP"}', "no req_id")],
    ids=["malformed", "no-req-id"],
)
def test_an_unusable_line_names_its_line_number(tmp_path, monkeypatch, bad, match):
    """A silently skipped line is a finding that vanishes from the assessment."""
    d = tmp_path / "sessions" / "s1"
    d.mkdir(parents=True)
    (d / "findings.jsonl").write_text('{"req_id": "V1.1.1", "verdict": "GAP"}\n' + bad + "\n")
    monkeypatch.setenv("OWASP_KB_STATE", str(tmp_path))
    with pytest.raises(RosterError, match=match) as exc:
        load_session_findings("s1")
    assert "line 2" in str(exc.value)


def test_blank_and_comment_lines_are_skipped(tmp_path, monkeypatch):
    d = tmp_path / "sessions" / "s1"
    d.mkdir(parents=True)
    (d / "findings.jsonl").write_text('# a note\n\n{"req_id": "V1.1.1", "verdict": "GAP"}\n\n')
    monkeypatch.setenv("OWASP_KB_STATE", str(tmp_path))
    assert len(load_session_findings("s1")) == 1


# -- the verification gate --------------------------------------------------


def _roster(findings, **kw):
    kw.setdefault("chapter_states", {"V6": "APPLIES", "V7": "APPLIES"})
    kw.setdefault("require_verification", False)
    return build_roster(requirements=REQS, findings=findings, **kw)


def test_complete_does_not_mean_verified(tmp_path):
    """complete is placement only: every requirement carries a verdict. It was
    read as 'the assessment is done', and a run shipped a report with 35 of 51
    gaps unverified while this field said true -- correctly, per its own
    contract. The two facts now have two fields."""
    result = _roster(
        [_f("V6.2.1", "V6", "V6.2", verdict="GAP (unconfirmed)", evidence="e", file="a.c", line=1)]
    )
    assert result["complete"] is True, "every requirement is still placed"
    assert result["verification_complete"] is False, "but nothing checked the claim"


def test_verification_complete_when_every_claim_met_its_adversary():
    """Every requirement reported on, every asserting claim checked."""
    result = _roster(
        [
            _f(
                "V6.2.1", "V6", "V6.2", verdict="GAP", evidence="e", file="a.c", line=1, cwe="CWE-1"
            ),
            _f("V6.2.2", "V6", "V6.2", verdict="MET", evidence="present"),
            _f("V7.1.1", "V7", "V7.1", verdict="MET", evidence="present"),
        ]
    )
    assert result["verification_complete"] is True
    assert result["unverified"] == {}
    assert result["unassessed"] == []


def test_unverified_counts_what_is_missing_per_verdict():
    """A single boolean cannot tell a caller what to dispatch. The counts can."""
    result = _roster(
        [
            _f(
                "V6.2.1",
                "V6",
                "V6.2",
                verdict="GAP (unconfirmed)",
                evidence="e",
                file="a.c",
                line=1,
            ),
            _f(
                "V6.2.2",
                "V6",
                "V6.2",
                verdict="GAP (unconfirmed)",
                evidence="e",
                file="b.c",
                line=2,
            ),
        ],
        chapter_states={"V6": "APPLIES", "V7": "N/A (unverified)"},
    )
    assert result["unverified"]["GAP (unconfirmed)"] == 2
    assert result["unverified"].get("N/A (unverified)"), "an unverified exemption also counts"


def test_a_fully_verified_roster_reports_no_shortfall():
    """The field must be able to say 'nothing outstanding', or a caller loops
    forever. An exempt chapter needs no findings -- its requirements are placed
    by chapter_states, not left unassessed."""
    result = _roster(
        [
            _f("V6.2.1", "V6", "V6.2", verdict="MET", evidence="present"),
            _f("V6.2.2", "V6", "V6.2", verdict="MET", evidence="present"),
        ],
        chapter_states={"V6": "APPLIES", "V7": "N/A (verified)"},
    )
    assert result["verification_complete"] is True
    assert result["unverified"] == {}
    assert result["unassessed"] == []


def test_a_requirement_nobody_looked_at_is_not_the_same_as_undeterminable():
    """Both are INSUFFICIENT EVIDENCE, and that is the problem. One means a
    finder reported it could not tell; the other means no finder ran. They were
    distinguishable only by finding_id being null, which nothing checked."""
    reported = _roster(
        [
            _f("V6.2.1", "V6", "V6.2", verdict="INSUFFICIENT EVIDENCE", evidence="could not tell"),
            _f("V6.2.2", "V6", "V6.2", verdict="MET", evidence="present"),
            _f("V7.1.1", "V7", "V7.1", verdict="MET", evidence="present"),
        ]
    )
    assert reported["counts"]["INSUFFICIENT EVIDENCE"] == 1
    assert reported["unassessed"] == [], "a finder did report on it"
    assert reported["verification_complete"] is True

    silent = _roster(
        [
            _f("V6.2.2", "V6", "V6.2", verdict="MET", evidence="present"),
            _f("V7.1.1", "V7", "V7.1", verdict="MET", evidence="present"),
        ]
    )
    assert silent["counts"]["INSUFFICIENT EVIDENCE"] == 1
    assert silent["unassessed"] == ["V6.2.1"], "nobody looked, and the id is what to dispatch"
    assert silent["verification_complete"] is False


# -- a refuted gap is not "nobody looked" (#64) ----------------------------


def test_a_refuted_gap_is_accepted_with_the_verifiers_trace():
    """A verifier disproved a reported gap. That is a determined outcome, and it
    is not MET: refuting the reported defect does not establish the control is
    adequate."""
    roster = build_roster(
        requirements=REQS,
        findings=[
            _f(
                "V6.2.1",
                "V6",
                "V6.2",
                verdict="INSUFFICIENT EVIDENCE (gap refuted)",
                file="src/net/connection_handler.c",
                line=212,
                trace="teardown clears the staging buffer at connection_handler.c:212",
            )
        ],
        chapter_states={"V6": "APPLIES", "V7": "N/A (verified)"},
    )
    assert roster["counts"]["INSUFFICIENT EVIDENCE (gap refuted)"] == 1


def test_a_refuted_gap_without_a_trace_is_rejected():
    """The verdict asserts a verifier ran. Without the trace it is a label
    anyone can apply, which is the reason a reason-field was not the design."""
    with pytest.raises(RosterError, match="owasp-finding-verifier"):
        build_roster(
            requirements=REQS,
            findings=[_f("V6.2.1", "V6", "V6.2", verdict="INSUFFICIENT EVIDENCE (gap refuted)")],
            chapter_states={"V6": "APPLIES", "V7": "N/A (verified)"},
        )


def test_the_refuted_gap_rejection_offers_the_plain_verdict_as_the_way_out():
    """Its fallback is plain INSUFFICIENT EVIDENCE -- no adversary was involved.
    Offering 'GAP (unconfirmed)' here, as the hardcoded message did, tells the
    caller to record a gap that a verifier just disproved."""
    with pytest.raises(RosterError) as excinfo:
        build_roster(
            requirements=REQS,
            findings=[_f("V6.2.1", "V6", "V6.2", verdict="INSUFFICIENT EVIDENCE (gap refuted)")],
            chapter_states={"V6": "APPLIES", "V7": "N/A (verified)"},
        )
    message = str(excinfo.value)
    assert "V6.2.1" in message
    assert "owasp-finding-verifier" in message
    assert "'INSUFFICIENT EVIDENCE'" in message
    assert "GAP (unconfirmed)" not in message


def test_every_adversary_fallback_is_a_real_verdict():
    """A fallback the roster would itself reject sends the caller in a circle."""
    for adversary, fallback in CLAIMS_NEEDING_AN_ADVERSARY.values():
        assert adversary.startswith("owasp-")
        assert fallback in VERDICTS
        assert fallback not in CLAIMS_NEEDING_AN_ADVERSARY, (
            f"{fallback!r} itself needs an adversary; recording it as the way out "
            "sends the caller right back through this same check"
        )


def test_a_refuted_gap_surfaces_for_attention_but_does_not_gate_the_report():
    """It is settled -- a verifier ran and returned -- so it is not outstanding
    work. But nobody made a positive statement about the control, so it must not
    read as a resolved requirement either."""
    roster = _roster(
        [
            _f(
                "V6.2.1",
                "V6",
                "V6.2",
                verdict="INSUFFICIENT EVIDENCE (gap refuted)",
                trace="teardown clears the buffer at connection_handler.c:212",
            ),
            _f("V6.2.2", "V6", "V6.2", verdict="MET", evidence="present"),
            _f("V7.1.1", "V7", "V7.1", verdict="MET", evidence="present"),
        ]
    )
    assert "V6.2.1" in {e["req_id"] for e in roster["needs_attention"]}
    assert roster["unassessed"] == []
    assert roster["verification_complete"] is True
    assert roster["by_chapter"]["V6"]["INSUFFICIENT EVIDENCE (gap refuted)"] == 1


def test_the_three_states_of_not_knowing_are_distinguishable():
    """#64: 32 of 253 requirements sat in one verdict meaning two things. Three
    facts, three states -- nobody looked, a finder could not tell, a verifier
    refuted the reported gap."""
    roster = _roster(
        [
            _f("V6.2.2", "V6", "V6.2", verdict="INSUFFICIENT EVIDENCE", evidence="could not tell"),
            _f(
                "V7.1.1",
                "V7",
                "V7.1",
                verdict="INSUFFICIENT EVIDENCE (gap refuted)",
                trace="input is length-checked at parser.c:88",
            ),
        ]
    )
    assert roster["counts"]["INSUFFICIENT EVIDENCE"] == 2, "V6.2.2 plus nobody-looked V6.2.1"
    assert roster["counts"]["INSUFFICIENT EVIDENCE (gap refuted)"] == 1
    assert roster["unassessed"] == ["V6.2.1"], "only the one no finder reported on"


def test_a_refuted_gap_citing_a_prior_assessment_is_rejected():
    """Unlike a plain INSUFFICIENT EVIDENCE, this verdict asserts that a specific
    mitigation exists at a specific place -- exactly the conclusion a prior
    report could hand it. It stays inside the exclusion scan (ADR 0011)."""
    with pytest.raises(RosterError, match="excluded"):
        build_roster(
            requirements=REQS,
            findings=[
                _f(
                    "V6.2.1",
                    "V6",
                    "V6.2",
                    verdict="INSUFFICIENT EVIDENCE (gap refuted)",
                    trace=f"already dismissed in {PRIOR}",
                )
            ],
            chapter_states={"V6": "APPLIES", "V7": "N/A (verified)"},
            excluded=[PRIOR],
        )
