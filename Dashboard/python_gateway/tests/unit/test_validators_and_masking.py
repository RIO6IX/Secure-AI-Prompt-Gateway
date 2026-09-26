from detection_engine.detectors.entropy_detector import shannon_entropy
from detection_engine.engine.masking import mask_value
from detection_engine.validators.email import is_email_valid
from detection_engine.validators.identifier import is_sri_lankan_nic_format
from detection_engine.validators.ip_address import is_ip_valid
from detection_engine.validators.luhn import is_luhn_valid


def test_luhn_validation_rejects_repeated_digits_and_accepts_test_visa() -> None:
    assert is_luhn_valid("4111 1111 1111 1111")
    assert not is_luhn_valid("0000 0000 0000 0000")
    assert not is_luhn_valid("4111-1111-1111-1112")


def test_basic_validators() -> None:
    assert is_email_valid("user@example.com")
    assert not is_email_valid("bad@@example")
    assert is_ip_valid("192.168.1.10")
    assert is_ip_valid("2001:db8::1")
    assert is_sri_lankan_nic_format("123456789V")
    assert is_sri_lankan_nic_format("200012345678")


def test_entropy_and_masking_do_not_expose_full_values() -> None:
    assert shannon_entropy("aB9xZ2mN7pQ4rT8v") > 3.0
    assert mask_value("EMAIL_ADDRESS", "amal@example.com") == "a***@example.com"
    assert mask_value("CREDIT_CARD_NUMBER", "4111 1111 1111 1111") == "**** **** **** 1111"
    assert "SuperSecret123" not in mask_value("PASSWORD", "SuperSecret123!")
