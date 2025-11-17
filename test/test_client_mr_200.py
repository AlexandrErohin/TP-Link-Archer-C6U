from unittest import main, TestCase
from unittest.mock import patch, MagicMock
from requests import Session
from tplinkrouterc6u import TPLinkMR200Client


class TestTPLinkMR200Client(TestCase):
    def setUp(self):
        self.obj = TPLinkMR200Client('', '')

    def test_supports_false(self):
        responses = [
            'var param1="0x1A"\nvar param2="0x2B"\nignored line\n',
            '404',
            'var nn="dfgdfg"\nvar ee="0x2B"\n'
        ]

        fake_responses = []
        for text in responses:
            r = MagicMock()
            r.text = text
            fake_responses.append(r)

        with patch.object(Session, "get", side_effect=fake_responses):
            for _ in range(len(fake_responses)):
                result = self.obj.supports()
                self.assertFalse(result)

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
