import struct
import socket


def ethernet_frame(bytes):
    """
    Extrage adresele mac destinatie si sursa, protocolul
si restul datelor din secventa de biti, procesata de portul RJ45
    :param bytes:
    :return:
    """
    dest_mac, src_mac, prot = struct.unpack('! 6s 6s H', bytes[:14])
    return addr_mac(dest_mac), addr_mac(src_mac), socket.htons(prot), bytes[14:]



def addr_mac(addr_bytes):
    """
    Proceseaza adresele mac in format lizibil omului
    :param addr_bytes:
    :return:
    """
    bytes_str = map('{:02x}'.format, addr_bytes)
    return ':'.join(bytes_str).upper()


def ipv4_packet(data):
    """
    Extragem versiunea, lungimea header-ului, time to live, protocolul si
adresele dint-un header de IPv4
    :param data:
    :return:
    """
    version_header_len= data[0]
    version = version_header_len >> 4
    header_len = (version_header_len & 15) * 4
    ttl, prot, src_ipv4, dest_ipv4 = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_len, ttl, prot, ipv4(src_ipv4), ipv4(dest_ipv4), data[header_len:]



def ipv4(addr):
    """
    Formateaza adresa IPv4 intr-un format lizibil omului
    :return:
    """
    return '.'.join(map(str,addr))

def icmp_packet(data):
    """
    Extrage tipul, codul, si campul de verificare dintr-un packet de ICMP
    :param data:
    :return:
    """
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


def tcp_segment(data):
    """
    Extragem informatii dintr-un segment de TCP
    :param data:
    :return:
    """
    (src_port, dst_port, sequence, acknowledgement, off_res_flag) = struct.unpack('! H H L L H', data[:14])
    offset = (off_res_flag >> 12) * 4
    flag_urg = (off_res_flag & 32) >> 5
    flag_ack = (off_res_flag & 16) >> 4
    flag_psh = (off_res_flag & 8) >> 3
    flag_rst = (off_res_flag & 4) >> 2
    flag_syn = (off_res_flag & 2) >> 1
    flag_fin = off_res_flag & 1
    return src_port, dst_port, sequence, acknowledgement, offset, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def udp_datagram(data):
    """
    Extragem informatii dintr-0 datagrama de UDP
    :param data:
    :return:
    """
    src_port, dst_port, length, checksum = struct.unpack('! H H H H', data[:8])
    return src_port, dst_port, length, checksum
























