from __future__ import annotations

POSITIVE_CONTEXT = {
    "CREDENTIAL": {
        "password", "passwd", "pwd", "token", "secret", "api key", "access key", "private key",
        "authorization", "bearer", "login", "credential", "oauth", "aws key",
    },
    "FINANCIAL": {
        "card", "credit card", "debit card", "pan", "account number", "cvv", "cvc",
        "security code", "expiry", "banking", "payment",
    },
    "PII": {
        "customer", "employee", "personal", "identity", "nic", "national identity card",
        "passport", "date of birth", "address", "phone", "email", "patient",
    },
    "SOURCE_CODE": {
        "proprietary", "confidential", "internal", "private repository", "production",
        "source code", "do not share", "trade secret", "company confidential",
    },
}
