"""Sri Lankan personal-name recognizer (deny-list style, as in Presidio).

spaCy's small English model misses many Sri Lankan names, especially at
the end of a sentence ("Invoice for Kamal Perera" gives no entity). A
common surname preceded by a capitalised given name or by initials is a
strong, low-noise signal:

    Kamal Perera, Nimali de Silva, K. Perera, A.B. Jayawardena,
    Priya Sivakumar, Fathima Rizwan

A surname on its own is not reported; many are also company or place
names (Perera & Sons, Fernando Mawatha).
"""

from __future__ import annotations

SURNAMES = (
    # Sinhala
    "Perera", "Fernando", "Silva", "Mendis", "Jayawardena", "Jayawardene", "Bandara", "Dissanayake",
    "Wickramasinghe", "Wickremesinghe", "Rajapaksa", "Rajapakse", "Gunawardena", "Gunawardene",
    "Herath", "Kumara", "Senanayake", "Ranasinghe", "Jayasinghe", "Rathnayake", "Ratnayake",
    "Weerasinghe", "Karunaratne", "Karunarathna", "Liyanage", "Wijesinghe", "Ekanayake",
    "Samarasinghe", "Amarasinghe", "Kumarasinghe", "Jayasuriya", "Gunasekara", "Gunasekera",
    "Wijeratne", "Wijerathne", "Rodrigo", "Peiris", "Pieris", "Dias", "Abeysekara", "Abeysekera",
    "Abeywardena", "Samaraweera", "Wanigasekara", "Munasinghe", "Premadasa", "Kodikara",
    "Madushanka", "Weerakkody", "Hettiarachchi", "Wickramaratne", "Seneviratne", "Senaratne",
    "Rathnayaka", "Dharmasena", "Madugalle", "Pathirana", "Kulatunga", "Jayalath", "Chandrasiri",
    "Wimalasena", "Galappaththi", "Dasanayake", "Nanayakkara", "Tennakoon", "Samaranayake",
    # Tamil
    "Sivakumar", "Rajendran", "Nadarajah", "Kanagaratnam", "Thevarajah", "Selvarajah", "Arulampalam",
    "Balasingham", "Sivanesan", "Ponnambalam", "Vigneswaran", "Kandiah", "Sivalingam", "Ratnam",
    "Shanmugam", "Murugan", "Thambipillai", "Sritharan", "Mahendran", "Kumaran", "Yogarajah",
    # Muslim / Malay
    "Mohamed", "Mohammed", "Rizwan", "Faizal", "Fazal", "Hameed", "Hussain", "Ismail", "Marikar",
    "Cassim", "Jaleel", "Rahman", "Nizam", "Farook", "Rafeek", "Azeez", "Saleem",
)

# Capitalised words that start sentences or greetings, not given names.
NOT_GIVEN_NAMES = (
    "Dear", "Hi", "Hello", "Hey", "Please", "Thanks", "Thank", "Regards", "From", "To", "Cc", "Attn",
    "Call", "Contact", "Ask", "Tell", "Email", "Send", "Invoice", "Customer", "Client", "Employee",
    "Manager", "Director", "Sir", "Madam", "Mr", "Mrs", "Ms", "Miss", "Dr", "Prof", "Rev", "The", "And",
    # request verbs that often start a prompt ("Refund Fathima Rizwan")
    "Refund", "Pay", "Charge", "Bill", "Assign", "Approve", "Approved", "Signed", "Meet", "Notify",
    "Remind", "Transfer", "Update", "Check", "Review", "Verify", "Reply", "Forward", "Write", "Draft",
    "Book", "Ship", "Deliver", "Invite", "Hire", "Onboard", "Promote", "Add", "Remove", "Find",
)

_SURNAME_ALT = "|".join(sorted(SURNAMES, key=len, reverse=True))
_NOT_GIVEN = "|".join(NOT_GIVEN_NAMES)

SRI_LANKAN_NAME_PATTERN = (
    r"\b(?:"
    # initials: "K. Perera", "A.B. Silva", "A. B. Silva"
    r"(?:[A-Z]\.\s?){1,3}\s?"
    r"|"
    # one or two given names that are not greeting/command words
    rf"(?:(?!(?:{_NOT_GIVEN})\b)[A-Z][a-z]{{1,20}}\s+){{1,2}}"
    r")"
    rf"(?:(?:de|De|da|Da)\s+)?(?:{_SURNAME_ALT})\b"
)
