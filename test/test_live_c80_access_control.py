"""Live block/unblock test against a real Archer C80 / C24.

Skipped unless these environment variables are set:
    TPLINK_HOST       e.g. http://192.168.0.1
    TPLINK_PASSWORD   router web password
    TPLINK_BLOCK_MAC  MAC of a spare device to block and unblock. Never the machine running the test.

Optional:
    TPLINK_USERNAME   defaults to admin

Run:
    TPLINK_HOST=http://192.168.0.1 TPLINK_PASSWORD=... TPLINK_BLOCK_MAC=AA-BB-CC-DD-EE-FF uv run pytest -m live -s

The test puts Access Control (on/off, blacklist/whitelist) back the way it found it,
and leaves the MAC blocked only if it was already blocked before the test.
"""
import os

import pytest

from tplinkrouterc6u.client.c80 import TplinkC80Router, RouterConstants

HOST = os.environ.get('TPLINK_HOST')
PASSWORD = os.environ.get('TPLINK_PASSWORD')
BLOCK_MAC = os.environ.get('TPLINK_BLOCK_MAC')
USERNAME = os.environ.get('TPLINK_USERNAME', 'admin')

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(not (HOST and PASSWORD), reason='TPLINK_HOST and TPLINK_PASSWORD not set'),
]


@pytest.fixture
def router():
    client = TplinkC80Router(HOST, PASSWORD, USERNAME, verify_ssl=False)
    client.authorize()
    try:
        yield client
    finally:
        client.logout()


def _access_control_switch(router: TplinkC80Router) -> dict[str, str]:
    request = RouterConstants.ACCESS_CONTROL_SWITCH_REQUEST
    return router._parse_last_values_from_block(router._return_data_block(request).get(request, []))


def _blocked_macs(router: TplinkC80Router) -> set[str]:
    return {device.macaddr for device in router.get_blocked_devices()}


def test_live_get_blocked_devices(router):
    devices = router.get_blocked_devices()
    print(f'\nAccess Control: {_access_control_switch(router)}')
    print(f'Blacklist ({len(devices)}): {[(d.macaddr, d.hostname) for d in devices]}')
    assert isinstance(devices, list)


@pytest.mark.skipif(not BLOCK_MAC, reason='TPLINK_BLOCK_MAC not set')
def test_live_block_then_unblock(router):
    mac = TplinkC80Router._format_mac(BLOCK_MAC)
    switch_before = _access_control_switch(router)
    was_blocked = mac in _blocked_macs(router)
    print(f'\nBefore: switch={switch_before} blocked={was_blocked}')

    try:
        router.block_device(mac, 'tplink-live-test')
        switch_after_block = _access_control_switch(router)
        print(f'After block: switch={switch_after_block}')
        assert mac in _blocked_macs(router)
        assert switch_after_block.get('ctrlEnable') == '1'
        assert switch_after_block.get('isWhiteList') == '0'

        if not was_blocked:
            router.unblock_device(mac)
            assert mac not in _blocked_macs(router)
            print('After unblock: removed from blacklist')
    finally:
        # Put Access Control back the way it was.
        if not was_blocked and mac in _blocked_macs(router):
            router.unblock_device(mac)
        if switch_before.get('isWhiteList') == '1':
            router._send_instruction('advanced bm -list white')
        if switch_before.get('ctrlEnable') == '0':
            router._send_instruction('advanced bm -disable')
        print(f'Restored: switch={_access_control_switch(router)}')
