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

    def test_get_lte_status(self):
        values = {
            '0': {
                'enable': '1',
                'connectStatus': '5',
                'networkType': '3',
                'simStatus': '5',
                'signalStrength': '4',
            },
            '1': {
                'totalStatistics': '81234567.0000',
                'curRxSpeed': '45120',
                'curTxSpeed': '9310',
            },
            '2': {'profileName': 'Carrier'},
        }

        with patch.object(TPLinkMR200Client, 'req_act', return_value=(0, values)), \
                patch.object(TPLinkMR200Client, 'get_sms', return_value=[]):
            status = self.obj.get_lte_status()

        self.assertEqual(status.enable, 1)
        self.assertEqual(status.connect_status, 5)
        self.assertEqual(status.network_type, 3)
        self.assertEqual(status.sim_status, 5)
        self.assertEqual(status.sig_level, 4)
        self.assertEqual(status.total_statistics, 81234567)
        self.assertEqual(status.cur_rx_speed, 45120)
        self.assertEqual(status.cur_tx_speed, 9310)
        self.assertEqual(status.isp_name, 'Carrier')
        self.assertEqual(status.sms_unread_count, 0)
        self.assertEqual(status.network_type_info, '4G LTE')
        self.assertEqual(status.sim_status_info, 'SIM unlocked. Authentication succeeded.')


if __name__ == '__main__':
    main()
