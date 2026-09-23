# Detection Engine Evaluation

How accurate and how fast the Component 01 Sensitive Data Detection Engine
is, and how to reproduce the numbers.

## Method

- **Dataset:** `python_gateway/evaluation/dataset.py` has 50 labelled
  prompts covering credentials, financial data and personal data. Every
  value is synthetic: vendor keys are built to the documented length from
  a fixed alphabet, and card numbers are issuer test numbers.
- **Hard negatives:** 18 of the prompts contain nothing sensitive but look
  sensitive to a naive scanner: UUIDs, commit hashes, order and invoice
  numbers, version numbers, URLs, release dates, "my password is too
  short", and all-caps words.
- **Matching:** a prediction is a true positive when its entity type
  matches the label and its span overlaps the labelled value. Any other
  prediction is a false positive, and any unmatched label is a false
  negative.
- **Not scored:** LOCATION and ORGANIZATION are low-risk context signals
  that the sanitizer leaves in place. SOURCE_CODE classifies the whole
  prompt rather than a span. Neither is scored.
- **Latency:** wall-clock time per `detect()` call on a developer laptop,
  with the spaCy `en_core_web_sm` model loaded.

Reproduce from `Dashboard/python_gateway`:

```
python -m evaluation.run --markdown
```

`tests/unit/test_benchmark.py` runs the same benchmark in the test suite.
It fails if overall precision or recall drops below 0.95.

## Results

| Entity type | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| ANTHROPIC_API_KEY | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| AWS_ACCESS_KEY | 3 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| AWS_SECRET_ACCESS_KEY | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| CREDIT_CARD_NUMBER | 4 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| CVV | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| DATABASE_CONNECTION_STRING | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| DATE_OF_BIRTH | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| EMAIL_ADDRESS | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| GITHUB_TOKEN | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| GOOGLE_API_KEY | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| HUGGINGFACE_TOKEN | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| IBAN | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| IP_ADDRESS | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| JWT_TOKEN | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| OPENAI_API_KEY | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| PASSPORT_NUMBER | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| PASSWORD | 3 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| PEM_PRIVATE_KEY | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| PERSON_NAME | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| PHONE_NUMBER | 2 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| SLACK_TOKEN | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| SLACK_WEBHOOK | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| SRI_LANKAN_NIC | 2 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| STRIPE_SECRET_KEY | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| SWIFT_BIC | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| **Overall** | 34 | 0 | 0 | **1.000** | **1.000** | **1.000** |

For larger inputs, the median latency on the same machine is about 23 ms
for 2,000 characters and 225 ms for 50,000 characters. NER is capped at
`NER_MAX_CHARS` (20,000 by default), while the regex, checksum and
entropy rules always scan the whole prompt.

## Adversarial (ReDoS) inputs

Prompts are attacker-controlled, so every rule was run against
50,000-character inputs built to trigger backtracking: long digit runs,
digit groups, dotted numbers, repeated "password is", `a@` runs,
base64-like runs, and 1,500 unterminated private-key headers. The slowest
took about 1 s (dotted numbers, where every quad is a valid IP). The rest
took 25-400 ms. `tests/unit/test_redos_guard.py` fails if any of them
exceeds 5 s.

## What the evaluation changed

The first run of this benchmark scored 0.919 precision. Its false
positives led to three fixes:

- One-word PERSON hits that are acronyms or sentence-initial words
  ("NIC", "Email the report ...") are dropped.
- A dotted quad after "version" is not reported as an IP address.
- Tokens inside URLs are not treated as high-entropy secrets.

Earlier probing also found problems that are now covered by unit tests:
the private-key body leaking, zero-width-character evasion, and the
password rule capturing ":".

## Limitations

- The dataset is small and was written by the developers. These scores
  are a regression gate, not proof of accuracy on real employee prompts.
  A production rollout should measure on a sample of real, consented and
  redacted prompts.
- NER uses the small English spaCy model. Sinhala and Tamil names and
  text are not covered.
- Proprietary source code is detected by heuristics and keywords only.
  There is no fingerprint index of the organisation's own repositories.
- Secrets without a vendor format are caught by entropy only when they
  appear next to a secret keyword or have high randomness. Short or
  word-like secrets without a "password"/"token" style label can be
  missed.
