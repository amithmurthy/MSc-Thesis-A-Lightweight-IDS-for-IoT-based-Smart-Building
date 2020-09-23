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
    client_to_server = 1
    server_to_client = 2
    client_to_local_network  = 3
    local_network_to_client = 4

def analyse_pcap(NetworkTraffic,file):
    ## Count limit is to limit processing for testing logic
    if count_limit is True:
        limit = 400000 #No of packets to process
    else:
        limit = math.inf
    count = 1
    device_traffic = collections.defaultdict(dict) #Key is the device mac address and values are packets incoming and outgoing from the device(all network interactions)
    non_ip_packets = []
    first_pkt_time = None
    for pkt_data,pkt_metadata in RawPcapReader(file):
        if count < limit:
            ether_pkt = Ether(pkt_data)
            if 'type' not in ether_pkt.fields:
                # Logic Link Control (LLC) frames will have 'len' instead of 'type'.
                # We disregard those
                continue
            ### MAC Address and IP address extraction and sorting traffic to each device ########

            packet_data = {}
            ipv = None
            if ether_pkt.src not in NetworkTraffic.mac_to_ip.keys():
                NetworkTraffic.mac_to_ip[ether_pkt.src] = None
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
                    NetworkTraffic.unique_ip.append(ip_pkt.src) #If its not in mac_to_ip then it won't be in list either so append. Saves another check just for the list
                elif ip_pkt.dst not in NetworkTraffic.unique_ip:
                    NetworkTraffic.unique_ip.append(ip_pkt.dst)
            packet_data['ordinal'] = count
            packet_data['eth_dst'] = ether_pkt.dst
            if count == 1:
                print("Test", count, first_pkt_time)
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
              Sorting incoming and outgoing traffic for each device 
            """
            if ether_pkt.src not in device_traffic.keys():
                device_traffic[ether_pkt.src] = {'incoming': None,
                                                 'outgoing': packet_data}
            if ether_pkt.dst not in device_traffic.keys():
                device_traffic[ether_pkt.dst] = {'incoming': packet_data,
                                                 'outgoing': None}
            else:
                device_traffic[ether_pkt.src]['outgoing'] = packet_data
                device_traffic[ether_pkt.dst]['incoming'] = packet_data

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
            direction = PktDirection.client_to_local_network
        elif ether_pkt.dst in NetworkTraffic.iot_mac_addr:
            direction = PktDirection.client_to_local_network
        else:
            direction = PktDirection.client_to_server
    print(direction)
    # elif ether_pkt.src in NetworkTraffic.non_iot.values():




def flow_filter(ip_pkt):
    pass


if __name__ == "__main__":
    NetworkTraffic = NetworkTrace("16-09-23.pcap")
    analyse_pcap(NetworkTraffic, "16-09-23.pcap")

