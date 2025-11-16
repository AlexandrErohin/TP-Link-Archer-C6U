from unittest import main, TestCase
from unittest.mock import patch, MagicMock
from requests import Session
from tplinkrouterc6u import TPLinkMR200Client


class TestTPLinkMR200Client(TestCase):
    def setUp(self):
        self.obj = TPLinkMR200Client('', '')

    def test_supports_false(self):
        fake_response1 = MagicMock()
        fake_response1.text = (
            'var param1="0x1A"\n'
            'var param2="0x2B"\n'
            'ignored line\n'
        )
        fake_response2 = MagicMock()
        fake_response2.text = '404'

        with patch.object(Session, "get", side_effect=[fake_response1, fake_response2]):
            result = self.obj.supports()

        self.assertEqual(result, False)

    def test_supports_true(self):
        fake_response = MagicMock()
        fake_response.text = (
            'var nn="0x1A"\n'
            'var ee="0x2B"\n'
        )

        with patch.object(Session, "get", return_value=fake_response):
            result = self.obj.supports()

        self.assertEqual(result, True)


if __name__ == '__main__':
    main()
