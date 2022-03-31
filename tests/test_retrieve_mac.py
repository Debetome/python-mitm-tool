import unittest
import binascii

from raw_mitm import MacRetriever
from raw_mitm.models import MacRetrieverArgs

from raw_mitm.logger import Logger as logger

retriever = MacRetriever(MacRetrieverArgs(
    router_ip="192.168.2.1",
    target_ip="192.168.2.2",
    your_mac="bc:5f:f4:00:a4:c9",
    your_ip="192.168.2.15",
    interface="enp1s0"
))

class TestRetrieveMac(unittest.TestCase):
    def test_retrieve_mac(self):
        try:
            logger.info("Retrieving ...")
            retriever.obtain()

            while True:
                if retriever.router_mac is not None:
                    break
                continue
            
            self.assertIsInstance(retriever.router_mac, bytes)
            self.assertIsInstance(retriever.target_mac, bytes)
            logger.info("Mac types are correct!")


        except Exception as ex:
            logger.error("Unable to retrieve mac addresses!")
            raise ValueError(ex)

        try:
            while True:
                if retriever.router_mac is not None:
                    break
                continue

            self.assertEqual(retriever.router_mac, retrievertarget_mac)
            logger.info(f"Router mac: {retriever.router_mac}")
            logger.info(f"Target mac: {retriever.target_mac}")
        except:
            logger.error("Mac addresses are equal!")
