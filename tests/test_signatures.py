import pytest


class TestSignatures:
    @staticmethod
    @pytest.mark.parametrize("sig, correct_int", [("blah", 9999), ("network_cnc_http", 41)])
    def test_get_category_id(sig, correct_int):
        from cape.signatures import get_category_id

        assert get_category_id(sig) == correct_int

    @staticmethod
    @pytest.mark.parametrize("sig, correct_string", [("blah", "unknown"), ("network_cnc_http", "Network")])
    def test_get_signature_category(sig, correct_string):
        from cape.signatures import get_signature_category

        assert get_signature_category(sig) == correct_string
