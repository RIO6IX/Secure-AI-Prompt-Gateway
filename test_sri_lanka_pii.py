from gliner import GLiNER

print("Loading local GLiNER-PII model...")

model = GLiNER.from_pretrained("./gliner-PII-model")

text = """
Mr. Kasun Perera works as a Finance Manager at LankaTech Solutions (Pvt) Ltd.

He lives at No. 45, Galle Road, Matara, Southern Province, Sri Lanka.

His National Identity Card number is 199812345678 and his passport number is N7654321.

His mobile number is +94 77 123 4567 and his email address is
kasun.perera@example.lk.

His bank account number is 012345678901 at Commercial Bank,
Matara Branch.

His credit card number is 4111 1111 1111 1111 and the card expiry date
is 12/29.

His employee number is EMP-4587 and his salary is LKR 185,000 per month.

The company server has the IP address 192.168.10.25.

His date of birth is 15 March 1998.

Customer Nadeesha Fernando purchased goods from ABC Garments PLC
and requested delivery to No. 17, Temple Road, Kandy.

The internal project password is TestPassword123 and the API key is
sk-test-123456789abcdef.
"""

labels = [
    "person",
    "organization",
    "job title",
    "address",
    "city",
    "province",
    "country",
    "bank",
    "date of birth",
]

entities = model.predict_entities(
    text,
    labels,
    threshold=0.6,
)

print("\nDetected contextual and sensitive entities:\n")

if not entities:
    print("No entities detected.")
else:
    for entity in entities:
        print(
            f"Text: {entity['text']}\n"
            f"Label: {entity['label']}\n"
            f"Score: {entity['score']:.4f}\n"
            f"Position: {entity['start']} - {entity['end']}\n"
            f"{'-' * 50}"
        )

print(f"\nTotal detected entities: {len(entities)}")