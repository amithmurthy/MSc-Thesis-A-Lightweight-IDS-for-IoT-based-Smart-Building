from scapy.all import *
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import TCP,UDP, IP, ICMP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment
from scapy.layers.dns import *
from enum import Enum
import time
import pickle
import math
from Dataset import NetworkTrace
from datetime import datetime, date
from PacketLevelSignature import GraphNetwork
from Device import DeviceProfile


"""Gloabl variables"""
count_limit = True
device_filter = False

class PktDirection(Enum):
    not_defined = 0
    iot_to_internet = 1
    internet_to_iot = 2
    iot_to_iot = 3
    iot_to_local_network = 4
    local_network_to_iot = 5
    internet_to_local_network = 6
    local_to_local = 7
    local_to_internet = 8


def analyse_pcap(NetworkTraffic, file, device_id):
    # Count limit is to limit processing for testing logic
    if count_limit is True:
        # No of packets to process
        limit = 1000
    else:
        limit = math.inf
    count = 0
    non_ip_packets = []
    first_pkt_time = None

    for pkt_data, pkt_metadata in RawPcapReader(file):
        packet_data = {}
        count += 1
        if count <= limit:
            ether_pkt = Ether(pkt_data)
            # if 'type' not in ether_pkt.fields:
            #     # Logic Link Control (LLC) frames will have 'len' instead of 'type'.
            #     # We disregard those
            #     continue
            """ MAC Address and IP address extraction and sorting traffic to each device """
            if device_filter is True:
                if ether_pkt.src != device_id and str(ether_pkt.dst) != device_id:
                    continue
            if ARP in ether_pkt:
                continue
            ipv = None
            if IP or IPv6 in ether_pkt:
                if IPv6 in ether_pkt:
                    ip_pkt = ether_pkt[IPv6]
                    ipv = 6
                    """ TCP payload: have to first check for ip fragmentation + different checks for ipv4 and ipv6."""
                    if ip_pkt.fields == 'M':
                        break
                elif IP in ether_pkt:
                    ip_pkt = ether_pkt[IP]
                    ipv = 4
                    if ip_pkt.fields == "MF" or ip_pkt.frag != 0:
                        # ip_pkt = ether_pkt[IPv6ExtHdrFragment]
                        print("IPv4 packet fragmentation")
            else:
                non_ip_packets.append(ether_pkt)

            if ether_pkt.src not in list(NetworkTraffic.mac_to_ip.keys()):
                NetworkTraffic.mac_to_ip[ether_pkt.src] = []
                NetworkTraffic.mac_to_ip[ether_pkt.src].append(ip_pkt.src)
            elif ether_pkt.src in list(NetworkTraffic.mac_to_ip.keys()):
                if ip_pkt.src not in NetworkTraffic.mac_to_ip[ether_pkt.src]:
                    NetworkTraffic.mac_to_ip[ether_pkt.src].append(ip_pkt.src)

            if ether_pkt.dst not in list(NetworkTraffic.mac_to_ip.keys()):
                NetworkTraffic.mac_to_ip[ether_pkt.dst] = []
                NetworkTraffic.mac_to_ip[ether_pkt.dst].append(ip_pkt.dst)
            elif ether_pkt.dst in list(NetworkTraffic.mac_to_ip.keys()):
                if ip_pkt.dst not in NetworkTraffic.mac_to_ip[ether_pkt.dst]:
                    NetworkTraffic.mac_to_ip[ether_pkt.dst].append(ip_pkt.dst)

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
            src_port = None
            dst_port = None
            protocol = None
            if TCP in ip_pkt:
                packet_data["protocol"] = "TCP"
                packet_data['tcp_data'] = tcp_info(ip_pkt, ipv)
                src_port = packet_data['tcp_data']['src_port']
                dst_port = packet_data['tcp_data']['dst_port']
                protocol = "tcp_data"
            elif UDP in ip_pkt:
                packet_data["protocol"] = "UDP"
                packet_data["udp_data"] = udp_info(ip_pkt, ipv)
                src_port = packet_data['udp_data']['src_port']
                dst_port = packet_data['udp_data']['dst_port']
                protocol = "udp_data"
                # if DNS in ip_pkt:
                #     dns_pkt = ip_pkt[DNS]
                #     if dns_pkt.qr == 0:
                #         domain_queried = dns_pkt.qd.qname
                #         packet_data["dns_query"] = domain_queried
                        # print(domain_queried)
                """ 
                        elif DNSRR in dns_pkt:
                            DNSRR is the response to the query     
                """

            elif ICMP in ip_pkt:
                packet_data["protocol"] = "ICMP"
                packet_data["icmp_data"] = icmp_info(ip_pkt, ipv)
                protocol = "icmp_data"
            # elif ARP in ether_pkt:
            #     packet_data["protocol"] = "ARP"
            #     protocol = "ARP"
            else:
                packet_data["protocol"] = "not defined yet"
                packet_data["payload_len"] = len(ip_pkt.payload)
                protocol = "unknown"
                # for layer in get_packet_layers(ether_pkt):
                #     print(layer.name,"/")

            # print(packet_data['relative_timestamp'])

            flow_tuple = (ip_pkt.src, ip_pkt.dst, src_port, dst_port, packet_data["protocol"])
            # if flow_tuple != ('52.87.241.159', '192.168.1.106', 443, 46330, "TCP"):
            #     continue
            # if flow_tuple != ('192.168.1.106', '52.87.241.159', 46330, 443, "TCP"):
            #     continue

            if flow_tuple in NetworkTraffic.flow_table:
                NetworkTraffic.flow_table[flow_tuple].append(packet_data)
            else:
                NetworkTraffic.flow_table[flow_tuple] = []
                NetworkTraffic.flow_table[flow_tuple].append(packet_data)
            """
                        Appending packet_data to device_traffic dictionary 
            """

            if ether_pkt.src not in NetworkTraffic.local_device_traffic.keys() and ether_pkt.src not in NetworkTraffic.device_traffic.keys():
                if ether_pkt.src in NetworkTraffic.internet_traffic:
                    NetworkTraffic.internet_traffic[ether_pkt.src].append(packet_data)
                else:
                    NetworkTraffic.internet_traffic[ether_pkt.src] = []
                    NetworkTraffic.internet_traffic[ether_pkt.src].append(packet_data)
            if ether_pkt.dst not in NetworkTraffic.local_device_traffic.keys() and ether_pkt.dst not in NetworkTraffic.device_traffic.keys():
                if ether_pkt.dst in NetworkTraffic.internet_traffic:
                    NetworkTraffic.internet_traffic[ether_pkt.dst].append(packet_data)
                else:
                    NetworkTraffic.internet_traffic[ether_pkt.dst] = []
                    NetworkTraffic.internet_traffic[ether_pkt.dst].append(packet_data)

            if packet_data['protocol'] == "TCP" or packet_data["protocol"] == "UDP":
                if ether_pkt.src in NetworkTraffic.keys_list:
                    # NetworkTraffic.device_traffic[ether_pkt.src].append(packet_data)
                    NetworkTraffic.sort_flow(flow_tuple, packet_data, "outgoing", protocol)
                if ether_pkt.dst in NetworkTraffic.keys_list:
                    # NetworkTraffic.device_traffic[ether_pkt.dst].append(packet_data)
                    NetworkTraffic.sort_flow(flow_tuple, packet_data, "incoming", protocol)


            if ether_pkt.src in NetworkTraffic.local_device_traffic:
                NetworkTraffic.local_device_traffic[ether_pkt.src].append(packet_data)
            if ether_pkt.dst in NetworkTraffic.local_device_traffic:
                NetworkTraffic.local_device_traffic[ether_pkt.dst].append(packet_data)


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

    if tcp_payload_len is None:
        tcp_payload_len = 0
    tcp_data['payload_len'] = tcp_payload_len

    if DNS in tcp_pkt:
        dns_pkt = tcp_pkt[DNS]
        print("DNS in TCP", dns_pkt.qr)

    return tcp_data

def udp_info(ip_pkt, ipv):
    udp_pkt = ip_pkt[UDP]
    udp_data = {'src_port': udp_pkt.sport, 'dst_port': udp_pkt.dport, 'payload_len': udp_pkt.len - 8}
    # UDP header is fixed at 8 bytes. Length field specifies length of header + data => len - 8 = payload
    return udp_data

def icmp_info(ip_pkt, ipv):
    icmp_pkt = ip_pkt[ICMP]
    icmp_data = {'payload_len': len(icmp_pkt.payload) - 8, 'type': icmp_pkt.type}
    return icmp_data


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
    # Need to check if just an else statement will work here
    elif ether_pkt.src not in NetworkTraffic.iot_mac_addr and NetworkTraffic.non_iot.values():
        if ether_pkt.dst in NetworkTraffic.iot_mac_addr:
            direction = PktDirection.internet_to_iot
        if ether_pkt.dst in NetworkTraffic.non_iot.values():
            direction = PktDirection.internet_to_local_network
    return direction

def pickle_file(traffic, pickle_file_out):
    with open(pickle_file_out, 'wb') as pickle_fd:
        pickle.dump(traffic, pickle_fd, protocol=pickle.HIGHEST_PROTOCOL)

def check_flows():
    for value in NetworkTraffic.iot_devices.values():
        if value in NetworkTraffic.flow_table.keys():
            print("Device", value, "has", len(NetworkTraffic.flow_table[value]), " flows")

def create_device_plots():
    # device_object_list = []
    for key in NetworkTraffic.iot_devices:
        addr = NetworkTraffic.iot_devices[key]
        if addr not in NetworkTraffic.mac_to_ip:
            print("key not in dict")
            continue
        iot_device = DeviceProfile(key, addr, NetworkTraffic.mac_to_ip[addr])
        iot_device.update_profile(NetworkTraffic.device_flows[addr])
        # device_object_list.append(iot_device)

def get_packet_layers(pkt):
    counter = 0
    while True:
        layer = pkt.getlayer(counter)
        if layer is None:
            break
        yield layer
        counter += 1



if __name__ == "__main__":
    NetworkTraffic = NetworkTrace("16-09-23.pcap")
    analyse_pcap(NetworkTraffic, "16-09-23.pcap", "30:8c:fb:2f:e4:b2")
    NetworkTraffic.flow_stats(NetworkTraffic.iot_devices["Dropcam"])
    # NetworkTraffic.flow_stats("14:cc:20:51:33:ea")
    # print(NetworkTraffic.device_flow_stats[NetworkTraffic.iot_devices["HP Printer"]])
    # NetworkTraffic.plot_device_flow(NetworkTraffic.iot_devices["TPLink Router Bridge LAN (Gateway)"])
    # print(NetworkTraffic.device_flows)
    # GraphNetwork.build_network(NetworkTraffic)

    # print(NetworkTraffic.device_flows)
    # print(NetworkTraffic.device_flow_stats)

    # dropcam = DeviceProfile("Dropcam", "30:8c:fb:2f:e4:b2", NetworkTraffic.mac_to_ip["30:8c:fb:2f:e4:b2"])
    # dropcam.update_profile(NetworkTraffic.device_flows["30:8c:fb:2f:e4:b2"])


