from unittest import main, TestCase
from unittest.mock import patch, MagicMock
from requests import Session
from tplinkrouterc6u import TPLinkVR400v2Client


class TestTPLinkVR400v2Client(TestCase):
    def setUp(self):
        self.obj = TPLinkVR400v2Client('', '')

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

    def test_supports_false_standard_mr200(self):
        # Scenario 1: Standard MR200 response (without userSetting)
        # VR400v2 should return False to let MR200Client handle it
        fake_response = MagicMock()
        fake_response.text = (
            'var nn="0x1A"\n'
            'var ee="0x2B"\n'
        )

        with patch.object(Session, "get", return_value=fake_response):
            result = self.obj.supports()

        self.assertEqual(result, False)

    def test_supports_true_vr400v2_style(self):
        # Scenario 2: VR400v2 style response with extra lines
        fake_response = MagicMock()
        fake_response.text = (
            'var userSetting=1;\n'
            'var ee="010001";\n'
            'var nn="0x123456";\n'
            '$.ret=0;\n'
        )

        with patch.object(Session, "get", return_value=fake_response):
            result = self.obj.supports()

        self.assertEqual(result, True)


if __name__ == '__main__':
    main()
