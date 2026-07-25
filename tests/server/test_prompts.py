from owasp_kb.server.prompts import build_prompts

TOOL_NAMES = {
    "kb_info", "owasp_search", "owasp_outline",
    "owasp_get", "owasp_checklist", "owasp_related",
}


def _by_name():
    return {p.__name__: p for p in build_prompts()}


def test_three_prompts_are_exposed():
    assert set(_by_name()) == {"asvs_chapter_review", "cheatsheet", "asvs_gap_report"}


def test_every_prompt_has_a_docstring():
    for prompt in build_prompts():
        assert prompt.__doc__ and prompt.__doc__.strip()


def test_chapter_review_prompt_names_the_tools_to_call():
    text = _by_name()["asvs_chapter_review"]("V6", "2")
    assert "owasp_checklist" in text
    assert "owasp_related" in text
    assert "V6" in text and "level 2" in text


def test_cheatsheet_prompt_orders_search_before_get():
    text = _by_name()["cheatsheet"]("file upload")
    assert text.index("owasp_search") < text.index("owasp_get")
    assert "file upload" in text


def test_gap_report_prompt_requires_citations_and_forbids_memory():
    text = _by_name()["asvs_gap_report"]("payments API", "2")
    assert "payments API" in text
    assert "cite" in text.lower()
    assert "from memory" in text.lower()


def test_every_prompt_forbids_answering_from_memory():
    for name, prompt in _by_name().items():
        text = prompt("x") if name == "cheatsheet" else prompt("x", "2")
        assert "from memory" in text.lower(), name


def test_prompts_only_reference_real_tools():
    """A prompt naming a tool that does not exist sends the agent nowhere."""
    import re

    for name, prompt in _by_name().items():
        text = prompt("x") if name == "cheatsheet" else prompt("x", "2")
        referenced = set(re.findall(r"\b(owasp_\w+|kb_info)\b", text))
        assert referenced <= TOOL_NAMES, f"{name} references unknown: {referenced - TOOL_NAMES}"


def test_gap_report_warns_against_sampling():
    """A compliance enumeration that silently samples is worse than none."""
    text = _by_name()["asvs_gap_report"]("api", "2")
    assert "do not sample" in text.lower() or "complete" in text.lower()


def test_prompts_have_sensible_defaults():
    prompts = _by_name()
    assert prompts["asvs_chapter_review"]("V6")
    assert prompts["asvs_gap_report"]("scope")
