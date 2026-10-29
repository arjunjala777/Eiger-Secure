"""Approval is server metadata, never a claim contained in document text.

User uploads remain available as private notes but cannot be evidence for bank
policy answers. Apply this constraint before ranking to resist context flooding.
"""

from halcyon.config import Settings
from halcyon.kb import Chunk, KnowledgeBase

MAX_CONTEXT_CHARS = 24_576


def enabled(settings: Settings) -> bool:
    return (settings.rag_approved_sources_only or settings.mode == "secure"
            or settings.profile == "production")


def retrieve_approved(kb: KnowledgeBase, query: str, session_id: str) -> list[Chunk]:
    # No fallback to an adapter that cannot filter before top-k.
    chunks = kb.retrieve(query, session_id, k=3, include_restricted=False, trusted_only=True)
    selected = []
    remaining = MAX_CONTEXT_CHARS
    for chunk in chunks:
        authorized = chunk.access == "public" or (
            chunk.access == "restricted" and bool(session_id) and chunk.owner_session == session_id
        )
        # Recheck the adapter's result; unknown labels fail closed.
        if chunk.provenance != "trusted" or not authorized:
            continue
        if len(chunk.text) > remaining:
            continue
        selected.append(chunk)
        remaining -= len(chunk.text)
    return selected
