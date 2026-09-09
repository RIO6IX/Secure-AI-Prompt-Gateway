"""Tests for temporary, non-persistent conversation context."""

import unittest

from app.conversation import ConversationStore, MAX_CONVERSATION_MESSAGES


class ConversationStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = ConversationStore()
        self.token = "fictional-session-token-one"

    def test_new_conversation_starts_without_context(self) -> None:
        conversation_id = self.store.create(self.token)

        messages = self.store.messages_for(
            self.token,
            conversation_id,
            "Fictional first prompt.",
        )

        self.assertEqual(
            messages,
            [{"role": "user", "content": "Fictional first prompt."}],
        )

    def test_successful_exchange_becomes_follow_up_context(self) -> None:
        conversation_id = self.store.create(self.token)
        self.store.commit_exchange(
            self.token,
            conversation_id,
            "Fictional approved prompt.",
            "Fictional assistant answer.",
        )

        messages = self.store.messages_for(
            self.token,
            conversation_id,
            "Fictional follow-up.",
        )

        self.assertEqual(len(messages), 3)
        self.assertEqual(messages[-1]["content"], "Fictional follow-up.")

    def test_conversations_are_isolated_by_session(self) -> None:
        conversation_id = self.store.create(self.token)

        with self.assertRaises(ValueError):
            self.store.messages_for(
                "fictional-session-token-two",
                conversation_id,
                "Fictional prompt.",
            )

    def test_clear_session_removes_all_session_context(self) -> None:
        conversation_id = self.store.create(self.token)
        self.store.clear_session(self.token)

        with self.assertRaises(ValueError):
            self.store.ensure_exists(self.token, conversation_id)

    def test_oldest_complete_exchanges_are_trimmed(self) -> None:
        conversation_id = self.store.create(self.token)
        exchange_count = (MAX_CONVERSATION_MESSAGES // 2) + 2

        for number in range(exchange_count):
            self.store.commit_exchange(
                self.token,
                conversation_id,
                f"Fictional prompt {number}.",
                f"Fictional response {number}.",
            )

        messages = self.store.messages_for(
            self.token,
            conversation_id,
            "Fictional final prompt.",
        )
        context = messages[:-1]

        self.assertLessEqual(len(context), MAX_CONVERSATION_MESSAGES)
        self.assertEqual(context[0]["role"], "user")
        self.assertNotIn("Fictional prompt 0.", str(context))


if __name__ == "__main__":
    unittest.main(verbosity=2)
