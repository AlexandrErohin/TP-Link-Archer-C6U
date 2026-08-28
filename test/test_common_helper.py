from unittest import TestCase, main

from tplinkrouterc6u.common.helper import escape_act_attr_value, unescape_act_attr_value


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


if __name__ == '__main__':
    main()
