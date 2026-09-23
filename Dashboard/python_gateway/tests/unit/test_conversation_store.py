import time

import pytest

from prompt_sanitizer import ConversationAccessError, ConversationStore, PseudonymMap


def test_pseudonym_map_is_stable_and_never_reuses_numbers() -> None:
    mapping = PseudonymMap()
    first = mapping.assign("EMAIL_ADDRESS", "a@b.lk", "a***@b.lk", True, avoid="")
    second = mapping.assign("EMAIL_ADDRESS", "c@d.lk", "c***@d.lk", True, avoid="")
    again = mapping.assign("EMAIL_ADDRESS", "a@b.lk", "a***@b.lk", True, avoid="")

    assert (first, second, again) == ("[EMAIL_ADDRESS_1]", "[EMAIL_ADDRESS_2]", "[EMAIL_ADDRESS_1]")


def test_pseudonym_map_holds_no_plaintext_unless_asked() -> None:
    mapping = PseudonymMap()
    mapping.assign("PASSWORD", "Sup3rS3cret!", "********", False, avoid="")
    assert "Sup3rS3cret!" not in repr(vars(mapping))

    keeping = PseudonymMap(keep_values=True)
    keeping.assign("PASSWORD", "Sup3rS3cret!", "********", False, avoid="")
    keeping.assign("EMAIL_ADDRESS", "a@b.lk", "a***@b.lk", True, avoid="")
    assert keeping.values == {"[EMAIL_ADDRESS_1]": "a@b.lk"}  # PII only, never credentials


def test_copy_isolates_uncommitted_assignments() -> None:
    mapping = PseudonymMap()
    mapping.assign("EMAIL_ADDRESS", "a@b.lk", "a***@b.lk", True, avoid="")
    working = mapping.copy()
    working.assign("EMAIL_ADDRESS", "c@d.lk", "c***@d.lk", True, avoid="")

    assert "[EMAIL_ADDRESS_2]" in working.masked
    assert "[EMAIL_ADDRESS_2]" not in mapping.masked
    assert working.assign("EMAIL_ADDRESS", "a@b.lk", "a***@b.lk", True, avoid="") == "[EMAIL_ADDRESS_1]"


def test_store_expires_idle_conversations_and_trims_history() -> None:
    store = ConversationStore(ttl_seconds=0.05, max_messages=4)
    conversation = store.open(None, "a@x.lk")
    for turn in range(3):
        store.record_exchange(conversation, conversation.mapping, f"q{turn}", f"a{turn}")
    assert [m["content"] for m in conversation.history()] == ["q1", "a1", "q2", "a2"]

    time.sleep(0.1)
    with pytest.raises(ConversationAccessError):
        store.open(conversation.id, "a@x.lk")


def test_store_rejects_other_owners_and_caps_size() -> None:
    store = ConversationStore(max_conversations=2)
    first = store.open(None, "a@x.lk")
    with pytest.raises(ConversationAccessError):
        store.open(first.id, "b@x.lk")
    store.open(None, "a@x.lk")
    store.open(None, "a@x.lk")
    with pytest.raises(ConversationAccessError):
        store.open(first.id, "a@x.lk")  # evicted as the oldest
