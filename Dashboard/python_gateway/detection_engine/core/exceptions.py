from __future__ import annotations


class DetectionError(Exception):
    code = "INTERNAL_ERROR"
    message = "Detection failed."

    def __init__(self, message: str | None = None, code: str | None = None) -> None:
        self.message = message or self.message
        self.code = code or self.code
        super().__init__(self.message)


class EmptyPromptError(DetectionError):
    code = "EMPTY_PROMPT"
    message = "Prompt must not be empty."


class PromptTooLargeError(DetectionError):
    code = "PROMPT_TOO_LARGE"
    message = "Prompt exceeds the configured maximum length."


class BatchTooLargeError(DetectionError):
    code = "BATCH_TOO_LARGE"
    message = "Batch exceeds configured limits."
