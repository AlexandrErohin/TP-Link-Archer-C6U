from decimal import Decimal

from tplinkrouterc6u.client.c80 import TplinkC80Router
from tplinkrouterc6u.common.dataclass import LTEStatus


class TplinkMR515Router(TplinkC80Router):
    """TP-Link Archer MR515 4G/LTE router (C80-style data-block protocol)."""

    # Unauthenticated probe of the LTE traffic-statistics block.
    # Before login the firmware acknowledges the block id; field payloads
    # (totalStatistics, speeds, …) are read later via authenticated _post_data.
    _LTE_TRAFFIC_BLOCK = '139|1,0,0'

    def supports(self) -> bool:
        """Match MR515 by an unauthenticated echo of LTE traffic block 139.

        Same pattern as ``TplinkC80Router.supports()`` (code=2, no token): only
        the block id is reliable pre-auth. Do not require statistics field names
        here — those appear after ``authorize()``.
        """
        try:
            response = self.request(2, 1, data=self._LTE_TRAFFIC_BLOCK)
            return (
                response.status_code == 200
                and response.text.startswith('00000')
                and f'id {self._LTE_TRAFFIC_BLOCK}' in response.text
            )
        except Exception:
            return False

    @staticmethod
    def _lte_int(value: str | None) -> int | None:
        """Convert an optional LTE field to an integer."""
        if value is None:
            return None
        try:
            return int(Decimal(value))
        except (ValueError, ArithmeticError):
            return None

    @staticmethod
    def _lte_bool(value: str | None) -> bool | None:
        """Convert an optional 0/1 LTE setting to a boolean."""
        parsed = TplinkMR515Router._lte_int(value)
        return bool(parsed) if parsed in (0, 1) else None

    @staticmethod
    def _lte_cell_value(values: dict[str, str], field: str, index: int = 1) -> int | None:
        """Read a field from the primary serving cell (servingCellList index 1)."""
        indexed = values.get(f'{field} {index}')
        if indexed is not None:
            return TplinkMR515Router._lte_int(indexed)
        # Some firmware revisions flatten the same indexed field with a prefix.
        for key, value in values.items():
            if key.endswith(f' {field} {index}'):
                return TplinkMR515Router._lte_int(value)
        # Retain compatibility with firmwares returning a non-indexed cell block.
        direct = values.get(field)
        return TplinkMR515Router._lte_int(direct)

    @staticmethod
    def _field_value(values: dict[str, str], field: str) -> str | None:
        """Find a field even when the firmware prefixes its nested model path."""
        if field in values:
            return values[field]
        return next((value for key, value in values.items()
                     if key.endswith(f' {field}')), None)

    @staticmethod
    def _connect_status(mobile_status: int | None) -> int | None:
        """Map firmware MOBILE_LINK_STATUS to LTEStatus.connect_status.

        On MR515, block 153 ``status`` uses ``2`` for connected (UI "Connected").
        Other non-None values map to ``0`` (not connected) so integrations that
        treat ``connect_status == 1`` as online keep working, same as Deco.
        """
        if mobile_status is None:
            return None
        return 1 if mobile_status == 2 else 0

    def get_lte_status(self) -> LTEStatus:
        """Read LTE status and traffic counters from Archer MR515 data blocks."""
        requests = {
            'traffic': self._LTE_TRAFFIC_BLOCK,
            'link': '140|1,0,0',
            'wan': '143|1,0,0',
            'profile': '144|1,0,0',
            'cell': '151|1,0,0',
            'mobile': '153|1,0,0',
        }
        data_blocks = self._return_data_block('#'.join(requests.values()))

        def block(name: str) -> dict[str, str]:
            return self._parse_last_values_from_block(data_blocks.get(requests[name], []))

        traffic = block('traffic')
        link = block('link')
        wan = block('wan')
        profile = block('profile')
        cell = block('cell')
        mobile = block('mobile')

        field = self._field_value
        mobile_status = self._lte_int(field(mobile, 'status'))

        return LTEStatus(
            enable=self._lte_int(field(wan, 'dataSwitchStatus')),
            connect_status=self._connect_status(mobile_status),
            network_type=self._lte_int(field(link, 'networkType')),
            sim_status=self._lte_int(field(link, 'simStatus')),
            total_statistics=self._lte_int(field(traffic, 'totalStatistics')),
            # Live rates are already bytes per second on this firmware.
            cur_rx_speed=self._lte_int(field(traffic, 'curRxSpeed')),
            cur_tx_speed=self._lte_int(field(traffic, 'curTxSpeed')),
            data_limit=self._lte_int(field(traffic, 'limitation')),
            enable_data_limit=self._lte_bool(field(traffic, 'enableDataLimit')),
            warning_percent=self._lte_int(field(traffic, 'warningPercent')),
            enable_payment_day=self._lte_bool(field(traffic, 'enablePaymentDay')),
            payment_day=self._lte_int(field(traffic, 'paymentDay')),
            adjust_statistics=self._lte_int(field(traffic, 'adjustStatistics')),
            sig_level=self._lte_int(field(link, 'signalStrength')),
            rsrp=self._lte_cell_value(cell, 'RSRP', index=1),
            rsrq=self._lte_cell_value(cell, 'RSRQ', index=1),
            # SNR is the firmware integer as reported (no extra scaling).
            snr=self._lte_cell_value(cell, 'SNR', index=1),
            isp_name=field(profile, 'ispName'),
        )
