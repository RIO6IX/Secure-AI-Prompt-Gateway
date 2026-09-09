"""
Fictional test data for the Secure AI Prompt Gateway.

Important:
- All names, identifiers, credentials, URLs, and numbers are fictional.
- Never place real employee, customer, banking, or secret data in this file.
"""


FICTIONAL_TEST_PROMPT = """
Please prepare a fictional employee access report.

Employee details:
Employee ID: EMP2048
EPF No: EPF778899
Staff ID: STF-4501
Customer ID: CUST-90021
Client Number: CL-778811

Personal identifiers:
Old NIC: 901234567V
Alternative old NIC: 851112223X
New NIC: 199012345678
Another new NIC: 200150178901
Passport Number: N1234567
Alternative Passport: P7654321

Contact details:
Primary email: kasun.perera@example.com
Secondary email: nadeesha.fernando@testcompany.lk
Sentence email: dilani.silva@example.org.
Mobile: +94 77 123 4567
Mobile without spaces: 0771234567
Mobile with dashes: 071-456-7890
Colombo landline: 011 234 5678
Kandy landline: +94 81 223 4567

Network and system details:
Public IP: 203.0.113.25
Internal IP: 192.168.10.25
Another internal IP: 10.20.30.40
Public URL: https://example.com/account/profile
Internal URL: http://192.168.10.25:8080/admin
Local URL: http://localhost:5000/login

Financial details:
Salary: LKR 250,000.00
Allowance: Rs. 45,500
Travel cost: LKR 12,750.50
Credit card: 4111 1111 1111 1111
Bank account number: 001234567890
Another account: 987654321012345

Dates:
Date of birth: 15/08/1990
Joining date: 2025-07-01
Review date: 04.08.2026

Credentials and secrets:
Password = FictionalPass123!
passwd: DemoPassword456$
pwd = SamplePwd789#
API key: demo_API_key_123456789
secret_key = fictionalSecretKey987654
access_token: token_ABCDEF1234567890
auth-token = AuthToken_XYZ987654321
JWT: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmaWN0aW9uYWwtdXNlciJ9.demoSignature123

Text that should not be incorrectly detected:
The meeting starts at 10.30 AM.
The report number is 12345.
The quantity is 250000.
The version is 1.2.3.
The username is kasun.perera.
The organization is ABC Garments PLC.
The test word is passwordless.
The email domain example.com is public.
Invalid old NIC: 999999999V
Invalid new NIC: 202399999999
Invalid date: 31/02/2026
Random number: 123456789012
Version: 2026.08.04
"""


EXPECTED_LABELS = {
    "EMPLOYEE_ID",
    "CUSTOMER_ID",
    "SRI_LANKAN_OLD_NIC",
    "SRI_LANKAN_NEW_NIC",
    "SRI_LANKAN_PASSPORT",
    "EMAIL",
    "SRI_LANKAN_PHONE",
    "IP_ADDRESS",
    "URL",
    "INTERNAL_URL",
    "LKR_AMOUNT",
    "CREDIT_CARD",
    "BANK_ACCOUNT",
    "DATE",
    "PASSWORD",
    "API_KEY",
    "JWT",
}


EXPECTED_EXAMPLES = {
    "EMPLOYEE_ID": [
        "EMP2048",
        "EPF778899",
        "STF-4501",
    ],
    "CUSTOMER_ID": [
        "CUST-90021",
        "CL-778811",
    ],
    "SRI_LANKAN_OLD_NIC": [
        "901234567V",
        "851112223X",
    ],
    "SRI_LANKAN_NEW_NIC": [
        "199012345678",
        "200150178901",
    ],
    "SRI_LANKAN_PASSPORT": [
    "N1234567",
    "P7654321",

    ],
    "EMAIL": [
        "kasun.perera@example.com",
        "nadeesha.fernando@testcompany.lk",
        "dilani.silva@example.org",
    ],
    "SRI_LANKAN_PHONE": [
        "+94 77 123 4567",
        "0771234567",
        "071-456-7890",
        "011 234 5678",
        "+94 81 223 4567",
    ],
    "IP_ADDRESS": [
        "203.0.113.25",
        "192.168.10.25",
        "10.20.30.40",
    ],
    "INTERNAL_URL": [
        "http://192.168.10.25:8080/admin",
        "http://localhost:5000/login",
    ],
    "URL": [
        "https://example.com/account/profile",
    ],
    "LKR_AMOUNT": [
        "LKR 250,000.00",
        "Rs. 45,500",
        "LKR 12,750.50",
    ],
    "CREDIT_CARD": [
        "4111 1111 1111 1111",
    ],
    "BANK_ACCOUNT": [
        "001234567890",
        "987654321012345",
    ],
    "DATE": [
        "15/08/1990",
        "2025-07-01",
        "04.08.2026",
    ],
    "PASSWORD": [
        "FictionalPass123!",
        "DemoPassword456$",
        "SamplePwd789#",
    ],
    "API_KEY": [
        "demo_API_key_123456789",
        "fictionalSecretKey987654",
        "token_ABCDEF1234567890",
        "AuthToken_XYZ987654321",
    ],
    "JWT": [
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmaWN0aW9uYWwtdXNlciJ9.demoSignature123",
    ],
}


SHOULD_NOT_BE_DETECTED = [
    "10.30",
    "12345",
    "250000",
    "1.2.3",
    "kasun.perera",
    "ABC Garments PLC",
    "passwordless",
    "999999999V",
    "202399999999",
    "31/02/2026",
    "123456789012",
    "2026.08.04",
]
