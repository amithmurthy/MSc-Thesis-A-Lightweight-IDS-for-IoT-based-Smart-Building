from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import TCP,UDP, IP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment
from enum import Enum
import time
import pickle
import collections
import math
from Dataset import NetworkTrace
from datetime import datetime, date

##Gloabl variables####
count_limit = True

class PktDirection(Enum):
    not_defined = 0
    iot_to_internet = 1
    internet_to_iot = 2
    iot_to_iot = 3
    iot_to_local_network  = 4
    local_network_to_iot = 5
    internet_to_local_network = 6
    local_to_local = 7
    local_to_internet = 8

def analyse_pcap(NetworkTraffic,file):
    ## Count limit is to limit processing for testing logic
    if count_limit is True:
        limit = 100 #No of packets to process
    else:
        limit = math.inf
    count = 1
    non_ip_packets = []
    first_pkt_time = None
    error_handling = []

    for pkt_data,pkt_metadata in RawPcapReader(file):
        packet_data = {}
        if count <= limit:
            ether_pkt = Ether(pkt_data)
            if 'type' not in ether_pkt.fields:
                # Logic Link Control (LLC) frames will have 'len' instead of 'type'.
                # We disregard those
                continue
            ### MAC Address and IP address extraction and sorting traffic to each device ########

            ipv = None
            if ether_pkt.src not in NetworkTraffic.mac_to_ip.keys():
                NetworkTraffic.mac_to_ip[ether_pkt.src] = None
            if ether_pkt.dst not in NetworkTraffic.mac_to_ip.keys():
                NetworkTraffic.mac_to_ip[ether_pkt.dst] = None
            if IP or IPv6 in ether_pkt:
                if IPv6 in ether_pkt:
                    ip_pkt = ether_pkt[IPv6]
                    ipv = 6
                    # Determing TCP payload: have to first check for ip fragmentation. Thus, different checks for ipv4 and ipv6.
                    if ip_pkt.fields == 'M':
                        break
                elif IP in ether_pkt:
                    ip_pkt = ether_pkt[IP]
                    ipv = 4
                    if ip_pkt.fields == "MF" or ip_pkt.frag != 0:
                        break
                if ip_pkt.src not in NetworkTraffic.mac_to_ip:
                    NetworkTraffic.mac_to_ip[ether_pkt.src] = ip_pkt.src
                elif ip_pkt.dst not in NetworkTraffic.mac_to_ip:
                    NetworkTraffic.mac_to_ip[ether_pkt.dst] = ip_pkt.dst
            packet_data['ordinal'] = count
            packet_data['eth_src'] = ether_pkt.src
            packet_data['eth_dst'] = ether_pkt.dst
            if count == 1:
                first_pkt_time, relative_ts  = get_timestamp(pkt_metadata, count)
                packet_data['relative_timestamp'] = relative_ts
            else:
                packet_data['relative_timestamp'] = get_timestamp(pkt_metadata, count,first_pkt_time)
            packet_data['ip_src'] = ip_pkt.src
            packet_data['ip_dst'] = ip_pkt.dst
            packet_data['direction'] = get_pkt_direction(NetworkTraffic,ether_pkt)
            """
            Perform TCP info check -> returns a list of features which is added to packet_data['tcp info']
            """
            if TCP in ip_pkt:
                packet_data['protocol'] = "TCP"
                packet_data['tcp_data'] = tcp_info(ip_pkt, ipv)
            elif UDP in ip_pkt:
                packet_data["protocol"] = "UDP"
                packet_data["udp_data"] = udp_info(ip_pkt, ipv)
            """
                        Appending packet_data to device_traffic dictionary 
            """

            if ether_pkt.src or ether_pkt.dst not in zip(NetworkTraffic.non_iot.values(), NetworkTraffic.iot_mac_addr):
                if ether_pkt.src in zip(NetworkTraffic.non_iot.values(), NetworkTraffic.iot_mac_addr):
                    if ether_pkt.dst in NetworkTraffic.internet_traffic.keys():
                        NetworkTraffic.internet_traffic[ether_pkt.dst].append(packet_data)
                    else:
                        # print(NetworkTraffic)
                        NetworkTraffic.internet_traffic[ether_pkt.dst] = []
                        NetworkTraffic.internet_traffic[ether_pkt.dst].append(packet_data)
                elif ether_pkt.dst in zip(NetworkTraffic.non_iot.values(), NetworkTraffic.iot_mac_addr):
                    print("src is internet", ether_pkt.src)
                    if ether_pkt.src in NetworkTraffic.internet_traffic.keys():
                        NetworkTraffic.internet_traffic[ether_pkt.src].append(packet_data)
                    else:
                        NetworkTraffic.internet_traffic[ether_pkt.src] = []
                        NetworkTraffic.internet_traffic[ether_pkt.src].append(packet_data)


            if ether_pkt.src or ether_pkt.dst in NetworkTraffic.device_traffic:
                if ether_pkt.src in NetworkTraffic.device_traffic and ether_pkt.dst not in NetworkTraffic.device_traffic:
                    NetworkTraffic.device_traffic[ether_pkt.src].append(packet_data)
                elif ether_pkt.dst in NetworkTraffic.device_traffic and ether_pkt.src not in NetworkTraffic.device_traffic:
                    NetworkTraffic.device_traffic[ether_pkt.dst].append(packet_data)
                if ether_pkt.src and ether_pkt.dst in NetworkTraffic.device_traffic:
                    NetworkTraffic.device_traffic[ether_pkt.src].append(packet_data)
                    NetworkTraffic.device_traffic[ether_pkt.dst].append(packet_data)


            if ether_pkt.src or ether_pkt.dst in NetworkTraffic.local_deivice_traffic.values():
                if ether_pkt.src in NetworkTraffic.local_deivice_traffic.values() and ether_pkt.dst not in NetworkTraffic.local_deivice_traffic.values():
                    NetworkTraffic.local_deivice_traffic[ether_pkt.src].append(packet_data)
                elif ether_pkt.dst in NetworkTraffic.local_deivice_traffic and ether_pkt.src not in NetworkTraffic.local_deivice_traffic:
                    NetworkTraffic.local_deivice_traffic[ether_pkt.dst].append(packet_data)
                elif ether_pkt.src and ether_pkt.dst in NetworkTraffic.local_deivice_traffic.values():
                    NetworkTraffic.local_deivice_traffic[ether_pkt.src].append(packet_data)
                    NetworkTraffic.local_deivice_traffic[ether_pkt.dst].append(packet_data)

            # if ether_pkt.dst in NetworkTraffic.device_traffic.keys():
            #     NetworkTraffic.device_traffic[ether_pkt.dst].append(packet_data)
            # elif ether_pkt.src and ether_pkt.dst not in NetworkTraffic.device_traffic or NetworkTraffic.
        count += 1




def tcp_info(ip_pkt, ipv):
    tcp_data = {}
    tcp_pkt = ip_pkt[TCP]
    tcp_data['src_port'] = tcp_pkt.sport
    tcp_data['dst_port'] = tcp_pkt.dport
    tcp_data['tcp_flags'] = str(tcp_pkt.flags)
    tcp_payload_len = None
    if ipv == 4:
        tcp_payload_len = ip_pkt.len - (ip_pkt.ihl * 4) - (tcp_pkt.dataofs * 4)
    elif ipv == 6:
        tcp_payload_len = ip_pkt.plen - (tcp_pkt.dataofs * 4)
    tcp_data['payload_len'] = tcp_payload_len
    return tcp_data

def udp_info(ip_pkt, ipv):
    udp_pkt = ip_pkt[UDP]
    udp_data = {}
    udp_data['src_port'] = udp_pkt.sport
    udp_data['dst_port'] = udp_pkt.dport
    #UDP header is fixed at 8 bytes. Length field specifies length of header + data => len - 8 = payload
    udp_data['payload_len'] = udp_pkt.len - 8
    return udp_data

def get_timestamp(pkt_metadata,count, *args):
    pkt_timestamp = (pkt_metadata.tshigh << 32) | pkt_metadata.tslow
    pkt_timestamp_resolution = pkt_metadata.tsresol
    return_tuple = False
    if len(args) != 0:
        first_pkt_time = args[0]
    if count == 1:
        first_pkt_timestamp = pkt_timestamp
        first_pkt_timestamp_resolution = pkt_timestamp_resolution
        first_pkt_ts = printable_timestamp(first_pkt_timestamp, first_pkt_timestamp_resolution)
        first_pkt_dt = datetime.strptime(first_pkt_ts, '%Y-%m-%d %H:%M:%S.%f')
        first_pkt_time = first_pkt_dt.time()
        return_tuple = True
    timestamp = printable_timestamp(pkt_timestamp, pkt_timestamp_resolution)
    date_time_obj = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S.%f')
    this_pkt_ts = date_time_obj.time()
    try:
        this_pkt_relative_timestamp = datetime.combine(date.today(), this_pkt_ts) - datetime.combine(date.today(),
                                                                                                     first_pkt_time)
    except UnboundLocalError as e:
        print(e)
    if return_tuple is False:
        return this_pkt_relative_timestamp
    else:
        return first_pkt_time, this_pkt_relative_timestamp

def printable_timestamp(ts, resol):
    ts_sec = ts // resol
    ts_subsec = ts % resol
    ts_sec_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts_sec))
    # return ts_sec_str, ts_subsec
    return '{}.{}'.format(ts_sec_str, ts_subsec)

def get_pkt_direction(NetworkTraffic, ether_pkt):
    direction = PktDirection.not_defined
    if ether_pkt.src in NetworkTraffic.iot_mac_addr:
        if ether_pkt.dst in NetworkTraffic.non_iot.values():
            direction = PktDirection.iot_to_local_network
        elif ether_pkt.dst in NetworkTraffic.iot_mac_addr:
            direction = PktDirection.iot_to_iot
        else:
            direction = PktDirection.iot_to_internet
    elif ether_pkt.src in NetworkTraffic.non_iot.values():
        if ether_pkt.dst in NetworkTraffic.iot_mac_addr:
            direction = PktDirection.local_network_to_iot
        elif ether_pkt.dst in NetworkTraffic.non_iot.values():
            direction = PktDirection.local_to_local
        else:
            direction = PktDirection.local_to_internet
    elif ether_pkt.src not in NetworkTraffic.iot_mac_addr and NetworkTraffic.non_iot.values(): #Need to check if just an else statement will work here
        if ether_pkt.dst in NetworkTraffic.iot_mac_addr:
            direction = PktDirection.internet_to_iot
        if ether_pkt.dst in NetworkTraffic.non_iot.values():
            direction = PktDirection.internet_to_local_network
    return direction


def flow_filter(ip_pkt):
    pass


def direction_stats(device):
    internet_to_device = 0
    device_to_internet = 0
    device_to_local = 0
    local_to_device = 0
    local_to_internet = 0
    internet_to_local = 0
    device_to_device = 0

    for device in NetworkTraffic.device_traffic:
        print(device)
        traffic = NetworkTraffic.device_traffic[device]
        input_count = 0
        output_count = 0
        for packet in traffic:
            if packet["eth_src"] == device:
                output_count += 1
            elif packet["eth_dst"] == device:
                input_count += 1

if __name__ == "__main__":
    NetworkTraffic = NetworkTrace("16-09-23.pcap")
    analyse_pcap(NetworkTraffic, "16-09-23.pcap")
    lifx = NetworkTraffic.iot_devices["Light Bulbs LiFX Smart Bulb"]
    tp_link_plug = NetworkTraffic.iot_devices["TP-Link Smart plug"]
    smart_camera = NetworkTraffic.iot_devices["Samsung SmartCam"]
    # direction_stats(smart_camera)

    print(NetworkTraffic.internet_traffic)