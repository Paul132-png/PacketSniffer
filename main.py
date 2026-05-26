"""
Packet Sniffer pentru Ethernet
"""
import socket
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
from collections import deque
import time
import threading
from functions import *

TAB1 = '\t - '
TAB2 = '\t\t - '
TAB3 = '\t\t\t - '

history = deque(maxlen=60)
packet_count = 0
lock = threading.Lock()

fig, ax = plt.subplots(figsize=(10, 4))

line, = ax.plot([], [], color='cyan', linewidth=1.5)
fill = ax.fill_between([], [], alpha=0.3, color='cyan')

ax.set_title("Pachete / secundă")
ax.set_ylabel("Packets/s")
ax.set_xlabel("Timp (secunde)")
ax.set_xlim(0, 60)
ax.set_ylim(0, 10)
ax.grid(True, alpha=0.3)
plt.tight_layout()

last_time = time.time()

def update_graph(frame):
    global fill, packet_count, last_time

    now = time.time()
    if now - last_time >= 1.0:
        with lock:
            count = packet_count
            packet_count = 0
        history.append(count)
        last_time = now

    x = list(range(len(history)))
    y = list(history)

    line.set_data(x, y)

    fill.remove()
    fill = ax.fill_between(x, y, alpha=0.3, color='cyan')

    ax.set_ylim(0, max(max(history, default=1), 1) * 1.2 + 1)

def sniffer():
    global packet_count
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

            if prot == 1:
                icmp_type, code, checksum = icmp_packet(data)
                print(TAB1 + 'ICMP Packet: ')
                print(TAB2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))

            elif prot == 6:
                src_port, dst_port, sequence, acknowledgement, offset, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, _ = tcp_segment(data)
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

        with lock:
            packet_count += 1

def main():
    t = threading.Thread(target=sniffer, daemon=True)
    t.start()

    ani = FuncAnimation(fig, update_graph, interval=100, cache_frame_data=False)
    plt.show(block=True)

main()
