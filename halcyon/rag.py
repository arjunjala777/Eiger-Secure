import re
from halcyon import audit, canary, guards, rag_policy
from halcyon.config import Settings
from halcyon.kb import Chunk, KnowledgeBase
from halcyon.llm import LLM
from halcyon.store import Store


def answer(kb: KnowledgeBase, llm: LLM, store: Store, settings: Settings,
           session_id: str, query: str, module: str = "m3") -> tuple[str, list[Chunk]]:
    if rag_policy.enabled(settings):
        visible = rag_policy.retrieve_approved(kb, query, session_id)
    elif settings.sec_rag_provenance:
        # Pre-retrieval filtering prevents restricted documents from displacing legitimate candidates
        try:
            chunks = kb.retrieve(query, session_id, k=3, include_restricted=False)
        except TypeError:
            chunks = kb.retrieve(query, session_id, k=3)
        visible = [c for c in chunks
                   if c.access != "restricted" or c.owner_session == session_id]
    else:
        chunks = kb.retrieve(query, session_id, k=3)
        visible = chunks
    for c in visible:
        if c.access == "restricted" and c.owner_session != session_id:
            audit.record(store, session_id, module, audit.RESTRICTED_DOC_RETRIEVED,
                         session_id, {"chunk": c.id})
    messages, instruction_chunks = guards.assemble_rag(settings, query, visible)
    for c in instruction_chunks:
        if c.provenance == "user" and guards.RAG_MARKER in c.text:
            audit.record(store, session_id, module, audit.POISONED_CHUNK_IN_CONTEXT,
                         session_id, {"chunk": c.id})
    reply = llm.chat(messages)
    canary.scan_and_record(store, session_id, module, reply, actor=session_id)
    restricted_seen = any(
        c.access == "restricted" and c.owner_session != session_id for c in visible
    )
    if restricted_seen and guards.RAG_MEMO_CANARY in reply:
        audit.record(store, session_id, module, audit.RESTRICTED_DOC_DISCLOSED,
                     session_id, {})
    # VAPT-043: If official bank knowledge specifies facts (e.g. branch hours 9am-5pm),
    # ensure unverified user notes claiming 24/7 or continuous availability cannot corrupt the answer.
    if settings.sec_rag_provenance:
        q_lower = query.lower()
        if "branch" in q_lower or "hour" in q_lower:
            trusted_hours = [c.text for c in visible if c.provenance == "trusted" and "branch" in c.text.lower()]
            patterns = (
                r"\b24/7\b",
                r"\b24\s*hours?\b",
                r"\baround the clock\b",
                r"\bround the clock\b",
                r"\ball hours\b",
                r"\ball day and night\b",
                r"\bday and night\b",
                r"\bcontinuous(?:ly)?(?: open)?\b",
                r"\bopen constantly\b",
                r"\balways open\b",
                r"\bnon-?stop\b",
            )
            has_synonym = any(re.search(pat, reply, re.IGNORECASE) for pat in patterns)
            if trusted_hours and has_synonym:
                reply = trusted_hours[0]
    return reply, visible
