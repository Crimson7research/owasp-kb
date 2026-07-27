from owasp_kb.core.chunking import DEFAULT_MAX_TOKENS, chunk_markdown, slugify

DOC = """# Authentication Cheat Sheet

Intro text.

## Password Storage

Use argon2id.

### Work Factors

Tune memory cost.

## Session Handling

Rotate on login.
"""

FENCED = """# Doc

## Example

Before.

```python
def a():
    ## not a heading
    return 1
```

After.
"""


def test_splits_on_h2_and_h3():
    chunks = chunk_markdown(DOC, title="Authentication Cheat Sheet")
    anchors = [c.anchor for c in chunks]
    assert "password-storage" in anchors
    assert "work-factors" in anchors
    assert "session-handling" in anchors


def test_heading_path_includes_ancestors():
    chunks = {c.anchor: c for c in chunk_markdown(DOC, title="Authentication Cheat Sheet")}
    assert chunks["work-factors"].heading_path == (
        "Authentication Cheat Sheet > Password Storage > Work Factors"
    )


def test_preamble_before_first_heading_is_kept():
    chunks = chunk_markdown(DOC, title="Authentication Cheat Sheet")
    assert any("Intro text." in c.text for c in chunks)


def test_never_splits_inside_a_fenced_code_block():
    chunks = chunk_markdown(FENCED, title="Doc")
    example = [c for c in chunks if c.anchor == "example"]
    assert len(example) == 1
    text = example[0].text
    assert text.count("```") % 2 == 0
    assert "not a heading" in text


def test_headings_inside_fences_do_not_create_sections():
    assert all(c.anchor != "not-a-heading" for c in chunk_markdown(FENCED, title="Doc"))


def test_tilde_fences_are_respected():
    doc = "# D\n\n## S\n\n~~~\n## not a heading\n~~~\n\ntail\n"
    chunks = chunk_markdown(doc, title="D")
    assert all(c.anchor != "not-a-heading" for c in chunks)


def test_ord_is_sequential_and_depth_recorded():
    chunks = chunk_markdown(DOC, title="Authentication Cheat Sheet")
    assert [c.ord for c in chunks] == list(range(len(chunks)))
    by_anchor = {c.anchor: c for c in chunks}
    assert by_anchor["password-storage"].depth == 2
    assert by_anchor["work-factors"].depth == 3


def test_oversized_section_splits_on_paragraph_and_keeps_anchor():
    body = "\n\n".join(f"Paragraph {i} " + "word " * 120 for i in range(12))
    chunks = chunk_markdown(f"# D\n\n## Big\n\n{body}\n", title="D", max_tokens=400)
    big = [c for c in chunks if c.anchor == "big"]
    assert len(big) > 1
    assert all(c.heading_path == "D > Big" for c in big)


def test_every_chunk_has_balanced_fences_when_a_section_is_split():
    """Splitting an oversized section must not cut a code block in half."""
    block = "```python\n" + "\n".join(f"line_{i} = {i}" for i in range(60)) + "\n```"
    doc = f"# D\n\n## S\n\nprose paragraph\n\n{block}\n\nmore prose\n"
    for chunk in chunk_markdown(doc, title="D", max_tokens=100):
        assert chunk.text.count("```") % 2 == 0, f"unbalanced fence in {chunk.text[:80]!r}"


def test_no_chunk_is_empty_or_whitespace_only():
    chunks = chunk_markdown(DOC, title="Authentication Cheat Sheet")
    assert all(c.text.strip() for c in chunks)


def test_heading_with_no_body_produces_no_chunk():
    doc = "# D\n\n## Empty\n\n## Has Body\n\ntext\n"
    anchors = [c.anchor for c in chunk_markdown(doc, title="D")]
    assert "empty" not in anchors
    assert "has-body" in anchors


def test_h4_and_deeper_stay_with_their_parent_section():
    doc = "# D\n\n## Parent\n\nintro\n\n#### Deep\n\ndetail\n"
    chunks = chunk_markdown(doc, title="D")
    assert [c.anchor for c in chunks] == ["parent"]
    assert "detail" in chunks[0].text


def test_document_with_no_headings_still_yields_a_chunk():
    chunks = chunk_markdown("# Only Title\n\njust prose\n", title="Only Title")
    assert len(chunks) == 1
    assert "just prose" in chunks[0].text


def test_empty_document_yields_no_chunks():
    assert chunk_markdown("", title="D") == []


def test_token_est_is_populated():
    assert all(c.token_est > 0 for c in chunk_markdown(DOC, title="D"))


def test_slugify_matches_github_anchor_style():
    assert slugify("Password Storage") == "password-storage"
    assert slugify("OAuth 2.0 & OIDC") == "oauth-20--oidc"


def test_repeated_headings_get_disambiguated_anchors():
    """sections carries UNIQUE(doc_id, anchor), so two 'Limitations' subsections
    under different parents must not collapse into one row and mis-cite each
    other's content. GitHub disambiguates the same way."""
    doc = (
        "# D\n\n## X-Frame-Options\n\nxfo intro\n\n### Limitations\n\nxfo limits\n\n"
        "## CSP frame-ancestors\n\ncsp intro\n\n### Limitations\n\ncsp limits\n"
    )
    chunks = chunk_markdown(doc, title="D")
    limitation_chunks = [c for c in chunks if c.anchor.startswith("limitations")]
    assert [c.anchor for c in limitation_chunks] == ["limitations", "limitations-1"]
    by_anchor = {c.anchor: c for c in limitation_chunks}
    assert by_anchor["limitations"].heading_path == "D > X-Frame-Options > Limitations"
    assert by_anchor["limitations-1"].heading_path == "D > CSP frame-ancestors > Limitations"
    assert "xfo limits" in by_anchor["limitations"].text
    assert "csp limits" in by_anchor["limitations-1"].text


def test_anchors_are_unique_per_document():
    doc = "# D\n\n" + "".join(f"## S{i}\n\n### Do\n\ntext {i}\n\n" for i in range(5))
    chunks = chunk_markdown(doc, title="D")
    do_anchors = [c.anchor for c in chunks if c.anchor.startswith("do")]
    assert do_anchors == ["do", "do-1", "do-2", "do-3", "do-4"]
    assert len(set(do_anchors)) == len(do_anchors)


def test_an_oversized_section_keeps_one_anchor_across_its_chunks():
    """Disambiguation is per section, not per chunk."""
    body = "\n\n".join(f"Paragraph {i} " + "word " * 120 for i in range(12))
    chunks = chunk_markdown(f"# D\n\n## Big\n\n{body}\n", title="D", max_tokens=400)
    assert len({c.anchor for c in chunks}) == 1
    assert chunks[0].anchor == "big"


def test_default_max_tokens_fits_the_embedder_window():
    """The default matches bge-small's 512-token window exactly. Larger chunks
    have their tails silently dropped from the vector index; smaller ones
    over-fragment and measurably worsen ranking (400 moved hybrid mean rank
    from 2.2 to 2.8)."""
    from owasp_kb.core.embed import MAX_LENGTH

    assert DEFAULT_MAX_TOKENS == MAX_LENGTH
