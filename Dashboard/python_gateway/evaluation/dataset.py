"""Labelled evaluation prompts for the detection engine.

Every value is synthetic. Keys are built from a fixed alphabet to the
vendor's documented length; card numbers are issuer test numbers or
Luhn-valid numbers that are not issued; names, emails and IDs are made up.

Each case lists the sensitive values it contains and their expected
entity type. Cases with no labels are hard negatives: text that looks
sensitive to a naive scanner (UUIDs, commit hashes, order numbers, URLs,
dates, password small-talk) and must produce no in-scope finding.
"""

from __future__ import annotations

from dataclasses import dataclass, field

ALNUM = "Q7wErT9yUi0pAs4dFg2hJk6lZx8cVb3nMq5W"
HEX = "0123456789abcdef"


def synthetic(length: int, alphabet: str = ALNUM) -> str:
    return (alphabet * (length // len(alphabet) + 1))[:length]


@dataclass(frozen=True)
class Case:
    prompt: str
    labels: tuple[tuple[str, str], ...] = field(default_factory=tuple)  # (entity_type, exact value)
    note: str = ""


PEM_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun\n"
    "VTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxK\n"
    "-----END RSA PRIVATE KEY-----"
)
AWS_KEY = "AKIAZ7Q2WJ5K3LMNOPQR"
AWS_SECRET = synthetic(36) + "a/B+"
OPENAI_KEY = "sk-proj-" + synthetic(48)
ANTHROPIC_KEY = "sk-ant-api03-" + synthetic(40)
GITHUB_TOKEN = "ghp_" + synthetic(36)
STRIPE_KEY = "sk_live_" + synthetic(24)
SLACK_TOKEN = "xoxb-" + synthetic(12, "0123456789") + "-" + synthetic(24)
GOOGLE_KEY = "AIza" + synthetic(35)
HF_TOKEN = "hf_" + synthetic(34)
JWT = "eyJhbGciOiJIUzI1NiJ9." + synthetic(24) + "." + synthetic(30)
DB_URL = "postgres://admin:Wint3rIsC0ming@10.20.30.40:5432/payments"
SLACK_HOOK = "https://hooks.slack.com/services/T0ABC1234/B0DEF5678/" + synthetic(24)

CASES: tuple[Case, ...] = (
    # --- credentials ------------------------------------------------------------
    Case(f"Why does boto3 fail? My key is {AWS_KEY} in us-east-1.", (("AWS_ACCESS_KEY", AWS_KEY),)),
    Case(f"aws_access_key_id={AWS_KEY}\naws_secret_access_key={AWS_SECRET}",
         (("AWS_ACCESS_KEY", AWS_KEY), ("AWS_SECRET_ACCESS_KEY", AWS_SECRET))),
    Case(f"export OPENAI_API_KEY={OPENAI_KEY}", (("OPENAI_API_KEY", OPENAI_KEY),)),
    Case(f"client = Anthropic(api_key='{ANTHROPIC_KEY}')", (("ANTHROPIC_API_KEY", ANTHROPIC_KEY),)),
    Case(f"git push fails with token {GITHUB_TOKEN}", (("GITHUB_TOKEN", GITHUB_TOKEN),)),
    Case(f"stripe.api_key = \"{STRIPE_KEY}\"", (("STRIPE_SECRET_KEY", STRIPE_KEY),)),
    Case(f"Bot token {SLACK_TOKEN} stopped working", (("SLACK_TOKEN", SLACK_TOKEN),)),
    Case(f"Maps key {GOOGLE_KEY} returns 403", (("GOOGLE_API_KEY", GOOGLE_KEY),)),
    Case(f"huggingface-cli login --token {HF_TOKEN}", (("HUGGINGFACE_TOKEN", HF_TOKEN),)),
    Case(f"Authorization header is {JWT}", (("JWT_TOKEN", JWT),)),
    Case(f"Connect using {DB_URL} and tell me why it times out", (("DATABASE_CONNECTION_STRING", DB_URL),)),
    Case(f"Webhook {SLACK_HOOK} posts twice", (("SLACK_WEBHOOK", SLACK_HOOK),)),
    Case(f"Is this key format right?\n{PEM_KEY}", (("PEM_PRIVATE_KEY", PEM_KEY),)),
    Case("the password is: correct-horse-battery", (("PASSWORD", "correct-horse-battery"),)),
    Case('DB_PASSWORD="Tr0ub4dor&3"', (("PASSWORD", "Tr0ub4dor&3"),)),
    Case("login with admin / password = Summer2026!", (("PASSWORD", "Summer2026!"),)),
    Case("key AKIA\u200bZ7Q2WJ5K3LMNOPQR hidden with a zero-width space",
         (("AWS_ACCESS_KEY", "AKIA\u200bZ7Q2WJ5K3LMNOPQR"),), "evasion"),
    Case("SECRET_KEY=django-insecure-8f#k2@x!q9z$w7v6u5\nDEBUG=True",
         (("GENERIC_API_KEY", "django-insecure-8f#k2@x!q9z$w7v6u5"),)),
    Case(f"client_secret={synthetic(24)}", (("GENERIC_API_KEY", synthetic(24)),)),
    Case("Authorization: Basic YWRtaW46U3VwM3JTM2NyZXQh", (("BASIC_AUTH_CREDENTIALS", "YWRtaW46U3VwM3JTM2NyZXQh"),)),

    # --- financial --------------------------------------------------------------
    Case("Refund card 4539 1488 0343 6467 please", (("CREDIT_CARD_NUMBER", "4539 1488 0343 6467"),)),
    Case("Amex 3782 822463 10005 was declined", (("CREDIT_CARD_NUMBER", "3782 822463 10005"),)),
    Case("card 5425-2334-3010-9903 exp 04/28 cvv 391",
         (("CREDIT_CARD_NUMBER", "5425-2334-3010-9903"), ("CVV", "391"))),
    Case("pay via 4539.1488.0343.6467", (("CREDIT_CARD_NUMBER", "4539.1488.0343.6467"),)),
    Case("Wire to IBAN GB82WEST12345698765432 today", (("IBAN", "GB82WEST12345698765432"),)),
    Case("SWIFT code DEUTDEFF for the transfer", (("SWIFT_BIC", "DEUTDEFF"),)),

    # --- personal data ----------------------------------------------------------
    Case("Email the report to nimal.perera@company.lk", (("EMAIL_ADDRESS", "nimal.perera@company.lk"),)),
    Case("Call the customer on +94 77 123 4567", (("PHONE_NUMBER", "+94 77 123 4567"),)),
    Case("Mobile 0712345678 after 5pm", (("PHONE_NUMBER", "0712345678"),)),
    Case("Customer NIC 199512345678 needs verification", (("SRI_LANKAN_NIC", "199512345678"),)),
    Case("Old NIC 857541234V on the form", (("SRI_LANKAN_NIC", "857541234V"),)),
    Case("My passport number is N1234567", (("PASSPORT_NUMBER", "N1234567"),)),
    Case("date of birth: 1995-03-14", (("DATE_OF_BIRTH", "1995-03-14"),)),
    Case("Server 192.168.10.25 is down", (("IP_ADDRESS", "192.168.10.25"),)),
    Case("Please draft a letter to Priya Fernando about her claim", (("PERSON_NAME", "Priya Fernando"),)),

    Case("Account number 1234567890123 at Commercial Bank", (("BANK_ACCOUNT_NUMBER", "1234567890123"),)),
    Case("My address is No. 25, Galle Road, Colombo 03", (("STREET_ADDRESS", "No. 25, Galle Road, Colombo 03"),)),
    Case("Mr. Kamal Perera and ms. nimali silva joined",
         (("PERSON_NAME", "Kamal Perera"), ("PERSON_NAME", "nimali silva"))),

    # --- hard negatives (must stay clean) --------------------------------------
    Case("Explain the difference between hashing and encryption."),
    Case("What is the capital of Sri Lanka?"),
    Case("Request id 3f2b1c9e-8a7d-4e6f-9b0a-1c2d3e4f5a6b failed with 500"),
    Case("Commit 9fceb02d0ae598e95dc970b74767f19372d61af8 broke the build"),
    Case("Order reference 1234567 shipped on 2024-05-12"),
    Case("Invoice 2024 0512 3345 is due next week"),
    Case("Order ref 123456789012 shipped"),
    Case("URGENT: the DATABASE migration is CRITICAL"),
    Case("I forgot my password yesterday, how do I reset it?"),
    Case("my password is too short, what are the rules?"),
    Case("clone https://github.com/RIO6IX/Secure-AI-Prompt-Gateway.git and run it"),
    Case("docs: https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage"),
    Case("upgrade to version 1.2.3.4 then restart"),
    Case("Release date: 2024-05-12"),
    Case("Order N1234567 shipped today"),
    Case("paste the token here and the api will respond"),
    Case("SELECT name FROM users WHERE id = 42"),
    Case("API_KEY=${API_KEY} is read from the environment"),
    Case("token: <your-token-here>"),
    Case("Open the account at the branch in Kandy"),
    Case("We sold 25 units on the road yesterday"),
    Case("Our company is based in the city centre near the main station."),
)

# Types the benchmark scores. LOCATION/ORGANIZATION hits are low-risk context
# signals (the sanitizer leaves them in place), and SOURCE_CODE is a
# whole-prompt classification rather than a span, so they are reported
# separately and do not count as false positives here.
IGNORED_TYPES = frozenset({"LOCATION", "ORGANIZATION", "SOURCE_CODE", "PRIVATE_SOURCE_CODE"})
