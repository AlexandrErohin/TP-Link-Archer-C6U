from unittest import TestCase, main

from tplinkrouterc6u.common.helper import (
    escape_act_attr_value,
    unescape_act_attr_value,
    is_valid_base64,
)


class TestActAttrValueEscaping(TestCase):
    def test_escape_newlines(self) -> None:
        self.assertEqual(escape_act_attr_value('Line one\nLine two'), 'Line one\x12Line two')

    def test_escape_carriage_returns(self) -> None:
        self.assertEqual(escape_act_attr_value('a\rb'), 'a\x11b')

    def test_unescape_round_trip(self) -> None:
        original = 'Line one\nLine two\r\nLine three'
        self.assertEqual(unescape_act_attr_value(escape_act_attr_value(original)), original)

    def test_plain_text_unchanged(self) -> None:
        self.assertEqual(escape_act_attr_value('test sms'), 'test sms')
        self.assertEqual(unescape_act_attr_value('test sms'), 'test sms')


class TestIsValidBase64(TestCase):
    def test_valid_base64(self) -> None:
        self.assertTrue(is_valid_base64('aGVsbG8gd29ybGQ='))

    def test_wrong_length_rejected(self) -> None:
        self.assertFalse(is_valid_base64('00000'))

    def test_marker_with_crlf_rejected(self) -> None:
        # "00006\r\n" (WR844N error code) is not valid base64: wrong length
        # and non-base64 chars.
        self.assertFalse(is_valid_base64('00006\r\n'))

    def test_non_base64_chars_rejected(self) -> None:
        self.assertFalse(is_valid_base64('00000foo!@#'))

    def test_padding_validation(self) -> None:
        self.assertFalse(is_valid_base64('aGVsbG8gd29ybGQ===='))


if __name__ == '__main__':
    main()
