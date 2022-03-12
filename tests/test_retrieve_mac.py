import unittest
import binascii

from raw_mitm import MacDiscoverer
from raw_mitm.models import (
    MacDiscoverArgs,
    EtherHeader
)

from raw_mitm.logger import Logger as logger

class TestRetrieveMac(unittest.TestCase):
    #def test_create_ether_header(self):
    #    try:
    #        m = MacDiscoverer(MacDiscoverArgs(
    #            router_ip="192.168.2.0",
    #            target_ip="192.168.2.2",
    #            your_mac="bc:5f:f4:00:a4:c9",
    #            your_ip="192.168.2.18",
    #            interface="enp1s0"
    #        ))

    #        router_ether = m.create_arp_header(EtherHeader(
    #            dest_mac=str("\xff" * 6).encode("utf-8"),
    #            source_mac=m.your_mac,
    #            protocol=m.protocol
    #        ))

    #        self.assertIsInstance(router_ether, bytes)

    #    except Exception as ex:
    #        logger.error("Unable to retrieve mac addresses!")
    #        raise ValueError(ex)

    def test_retrieve_mac(self):
        try:
            m = MacDiscoverer(MacDiscoverArgs(
                router_ip="192.168.2.1",
                target_ip="192.168.2.2",
                your_mac="bc:5f:f4:00:a4:c9",
                your_ip="192.168.2.18",
                interface="enp1s0"
            ))
            m.obtain()

        except Exception as ex:
            logger.error("Unable to retrieve mac addresses!")
            raise ValueError(ex)
