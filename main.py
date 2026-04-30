"""
Packet Sniffer pentru Ethernet
"""
import socket
from functions import *
TAB1 = '\t - '
TAB2 = '\t\t - '
TAB3 = '\t\t\t - '
TAB4 = '\t\t\t\t - '

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, protocol, data = ethernet_frame(raw_data)

        if protocol == 8:
            (version, header_len, ttl, prot, src, dst, data) = ipv4_packet(data)
            print(TAB1 + 'IPv4 Packet:')
            print(TAB2 + 'Version: {}, Header Length: {}, Time To Live: {}\n'.format(version, header_len, ttl))
            print(TAB2 + 'Protocol: {}'.format(prot))
            print(TAB3 + 'Source IP: {}, Destination IP: {}'.format(src, dst))














main()