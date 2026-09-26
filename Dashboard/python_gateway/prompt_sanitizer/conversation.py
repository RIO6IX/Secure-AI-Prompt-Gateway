"""Sanitized multi-turn conversations (Component 02).

A chat is only useful if the model sees earlier turns ("make it shorter",
"now in Sinhala"). Sending history through a DLP gateway needs two things:

- the history the model sees must be the *sanitized* text, and
- a value must keep the same placeholder in every turn, which the
  conversation's PseudonymMap provides.

Conversations live in memory only, belong to the user who started them,
expire after CONVERSATION_TTL_MINUTES of inactivity and keep at most
CONVERSATION_MAX_MESSAGES messages. Nothing here is written to disk; the audit
log records each prompt separately.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from uuid import uuid4

from prompt_sanitizer.sanitizer import PseudonymMap


class ConversationAccessError(Exception):
    """Raised when a conversation id is unknown, expired or owned by someone else."""


@dataclass
class Conversation:
    id: str
    owner: str
    mapping: PseudonymMap
    messages: list[dict[str, str]] = field(default_factory=list)
    last_used: float = field(default_factory=time.monotonic)

    def history(self) -> list[dict[str, str]]:
        return list(self.messages)


class ConversationStore:
    def __init__(
        self,
        ttl_seconds: float = 30 * 60,
        max_messages: int = 20,
        max_conversations: int = 1000,
    ) -> None:
        self.ttl_seconds = ttl_seconds
        self.max_messages = max_messages
        self.max_conversations = max_conversations
        self._items: OrderedDict[str, Conversation] = OrderedDict()
        self._lock = threading.Lock()

    def _expire(self, now: float) -> None:
        for conversation_id in [cid for cid, item in self._items.items() if now - item.last_used > self.ttl_seconds]:
            del self._items[conversation_id]

    def open(self, conversation_id: str | None, owner: str, keep_values: bool = False) -> Conversation:
        """Return the caller's conversation, or start a new one when no id is given.

        An unknown, expired or foreign id raises ConversationAccessError rather
        than silently starting over, so the client knows its context is gone.
        """
        now = time.monotonic()
        with self._lock:
            self._expire(now)
            if conversation_id is None:
                conversation = Conversation(id=f"conv-{uuid4().hex}", owner=owner, mapping=PseudonymMap(keep_values))
                self._items[conversation.id] = conversation
                while len(self._items) > self.max_conversations:
                    self._items.popitem(last=False)
                return conversation
            conversation = self._items.get(conversation_id)
            if conversation is None or conversation.owner != owner:
                raise ConversationAccessError("Conversation not found or expired. Start a new chat.")
            conversation.last_used = now
            self._items.move_to_end(conversation_id)
            return conversation

    def record_exchange(self, conversation: Conversation, mapping: PseudonymMap, user_text: str, assistant_text: str) -> None:
        """Commit a forwarded exchange: the sanitized prompt, the raw model reply
        (which only ever saw placeholders) and the updated placeholder map."""
        with self._lock:
            conversation.mapping = mapping
            conversation.messages.extend((
                {"role": "user", "content": user_text},
                {"role": "assistant", "content": assistant_text},
            ))
            del conversation.messages[:-self.max_messages]
            conversation.last_used = time.monotonic()

    def discard(self, conversation_id: str, owner: str) -> bool:
        with self._lock:
            conversation = self._items.get(conversation_id)
            if conversation is None or conversation.owner != owner:
                return False
            del self._items[conversation_id]
            return True

    def active_count(self) -> int:
        with self._lock:
            self._expire(time.monotonic())
            return len(self._items)

    def reset(self) -> None:
        with self._lock:
            self._items.clear()
