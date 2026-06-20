import unittest

from ui_server import _validate_auth_email


class AuthEmailValidationTests(unittest.TestCase):
    def test_accepts_normal_email_and_normalizes_case(self):
        self.assertEqual(_validate_auth_email(" Analyst.User1@Gmail.COM "), "analyst.user1@gmail.com")

    def test_rejects_numeric_only_local_part(self):
        with self.assertRaisesRegex(ValueError, "letters before @"):
            _validate_auth_email("12234@gmail.com")

    def test_rejects_numeric_and_symbol_local_part(self):
        with self.assertRaisesRegex(ValueError, "valid email"):
            _validate_auth_email("123123+@gmail.com")

    def test_rejects_plus_addressing_for_signup(self):
        with self.assertRaisesRegex(ValueError, "valid email"):
            _validate_auth_email("hehe+@gmail.com")

    def test_rejects_common_domain_typo(self):
        with self.assertRaisesRegex(ValueError, "gmail.com"):
            _validate_auth_email("adsaf@gmai.co")

    def test_rejects_invalid_shape(self):
        with self.assertRaisesRegex(ValueError, "valid email"):
            _validate_auth_email("analyst@@gmail.com")


if __name__ == "__main__":
    unittest.main()
