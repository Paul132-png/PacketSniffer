"""
Packet Sniffer pentru Ethernet
"""
import socket
import matplotlib.pyplot as plt
from collections import deque
import time
from functions import *

TAB1 = '\t - '
TAB2 = '\t\t - '
TAB3 = '\t\t\t - '

history = deque(maxlen=60)
fig, ax = plt.subplots(figsize=(10, 4))
plt.ion()

line, = ax.plot([], [], color='cyan', linewidth=1.5)
fill = ax.fill_between([], [], alpha=0.3, color='cyan')

ax.set_title("Pachete / secundă")
ax.set_ylabel("Packets/s")
ax.set_xlabel("Timp (secunde)")
ax.set_xlim(0, 60)
ax.grid(True, alpha=0.3)
plt.tight_layout()

def update_graph(packet_count):
    global fill
    history.append(packet_count)
    x = list(range(len(history)))
    y = list(history)

    line.set_data(x, y)

    fill.remove()
    fill = ax.fill_between(x, y, alpha=0.3, color='cyan')

    ax.set_ylim(0, max(history, default=1) * 1.2 + 1)

    fig.canvas.draw_idle()
    fig.canvas.flush_events()

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    packet_count = 0
    last_time = time.time()

    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, protocol, data = ethernet_frame(raw_data)

        if protocol == 8:
            (version, header_len, ttl, prot, src, dst, data) = ipv4_packet(data)
            print(TAB1 + 'IPv4 Packet:')
            print(TAB2 + 'Version: {}, Header Length: {}, Time To Live: {}\n'.format(version, header_len, ttl))
            print(TAB2 + 'Protocol: {}'.format(prot))
            print(TAB3 + 'Source IP: {}, Destination IP: {}'.format(src, dst))

            if prot == 1:
                icmp_type, code, checksum = icmp_packet(data)
                print(TAB1 + 'ICMP Packet: ')
                print(TAB2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))

            elif prot == 6:
                src_port, dst_port, sequence, acknowledgement, offset, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin = tcp_segment(data)
                print(TAB1 + 'TCP Segment: ')
                print(TAB2 + 'SRC Port: {}, DST Port: {}'.format(src_port, dst_port))
                print(TAB2 + 'Sequence: {}, Acknowledgement: {}'.format(sequence, acknowledgement))
                print(TAB2 + 'Flags: ')
                print(TAB3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))

            elif prot == 17:
                src_port, dst_port, length, checksum = udp_datagram(data)
                print(TAB1 + 'UDP Datagram: ')
                print(TAB2 + 'SRC Port: {}, DST Port: {}'.format(src_port, dst_port))
                print(TAB2 + 'Length: {}, Checksum: {}'.format(length, checksum))

        now = time.time()
        if now - last_time >= 1.0:
            update_graph(packet_count)
            packet_count = 0
            last_time = now
        else:
            packet_count += 1

main()
