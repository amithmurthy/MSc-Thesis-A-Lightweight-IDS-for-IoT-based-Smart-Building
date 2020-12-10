# from device import DeviceProfile
import matplotlib.pyplot as plt
import numpy as np
from pylab import *
import scipy.stats
""""
This module is for calculating stats on Device objects
"""



def model_device_behaviour(device_trafic_objects, dates,mal_flows):
    """
    :param device_trafic_objects: list of DeviceProfile objects which contain the traffic of the day
    :param date: date of the malicious flows
    :param mal_flows:
    :return:
    """
    avg_input_rate = []
    avg_output_rate = []
    avg_input_pkt_rate = []
    avg_output_pkt_rate = []
    time = []
    total_traffic_size = []
    input_traffic_size = []
    output_traffic_size = []
    in_flows = []
    out_flows = []
    days = 0
    keys = list(mal_flows.keys())
    for date in dates:
        print(date)
        if date in keys:
            malicious_flows = mal_flows[date]
        else:
            malicious_flows = []
    in_benign_flow_sizes = []
    in_benign_flow_duration = []
    out_benign_flow_duration = []
    out_benign_flow_sizes = []
    in_mal_flow_sizes = []
    in_mal_flow_duration = []
    out_mal_flow_sizes = []
    out_mal_flow_duration = []
    input_pkt_sizes = []
    output_pkt_sizes = []
    for device_obj in device_trafic_objects:
        days += 1
        total_traffic = 0
        device_obj.update_profile([], [])
        # analyse_pkt_order(device_obj, "incoming")
        # get_input_jitter(device_obj)
        # input_stats = get_avg_input_stats(device_obj, malicious_flows)
        # output_stats = get_avg_output_stats(device_obj, malicious_flows)
        # in_mal_flow_sizes.append(input_stats['mal_flow_sizes'])
        # in_mal_flow_duration.append(input_stats['mal_flow_duration'])
        # in_benign_flow_sizes.append(input_stats['benign_flow_sizes'])
        # in_benign_flow_duration.append(input_stats['benign_flow_duration'])
        # out_mal_flow_sizes.append(output_stats['mal_flow_sizes'])
        # out_mal_flow_duration.append(output_stats['mal_flow_duration'])
        # out_benign_flow_sizes.append(output_stats['benign_flow_sizes'])
        # out_benign_flow_duration.append(output_stats['benign_flow_duration'])
        # avg_input_rate.append(input_stats['avg_rate'])
        # avg_input_pkt_rate.append(input_stats['pkt_rate'])
        # avg_output_rate.append(output_stats['avg_rate'])
        # avg_output_pkt_rate.append(output_stats['pkt_rate'])
        # input_traffic_size.append(input_stats['size'] / 1000000)
        # output_traffic_size.append(output_stats['size'] / 1000000)
        # total_traffic += (input_stats['size'] / 1000000) + (output_stats['size'] / 1000000)
        # total_traffic_size.append(total_traffic)
        # in_flows.append(input_stats['flows'])
        # out_flows.append(output_stats['flows'])
        input_pkt_sizes.extend(get_input_pkt_sizes(device_obj))
        output_pkt_sizes.extend(get_output_pkt_sizes(device_obj))
        time.append(days)

    # if len(device_trafic_objects) > 0:
    device_name = device_trafic_objects[0].device_name
    file_name = "plots/_" + device_name
    # file_name = "attack/_" + device_name
    pkt_size_cdf(input_pkt_sizes, output_pkt_sizes, file_name)
    # plot_flow_direction(time, avg_input_rate, avg_output_rate, "byte_rate", file_name)
    # plot_flow_direction(time, avg_input_pkt_rate, avg_output_pkt_rate, "pkt_rate", file_name)
    # plot_flow_direction(time, input_traffic_size, output_traffic_size, "size", file_name)
    # plot_flow_direction(time, in_flows, out_flows, "flows", file_name)
    # plot_input_flow_graph(time, input_traffic_size, file_name)
    return device_name + "done"
    # else:
    #     return "done"

    # def create_graphs():
    #      pass
        # plot(time, total_traffic_size, file_name)
        # plot_flow_direction(time, avg_input_rate, avg_output_rate, "byte_rate", file_name)
        # plot_flow_direction(time, avg_input_pkt_rate, avg_output_pkt_rate, "pkt_rate", file_name)
        # plot_flow_direction(time, input_traffic_size, output_traffic_size,"size", file_name)
        # plot_flow_direction(time, in_flows, out_flows, "flows", file_name)
        # plot_input_flow_graph(time, input_traffic_size, file_name)

        # if len(in_mal_flow_sizes) > 0:
        #     for i in range(0, len(in_mal_flow_sizes), 1):
        #         plot_flow_size(in_benign_flow_sizes[i], in_benign_flow_duration[i], in_mal_flow_sizes[i], in_mal_flow_duration[i], "input", file_name, i)
        # if len(out_mal_flow_sizes) > 0:
        #     for i in range(0, len(out_mal_flow_sizes), 1):
        #         plot_flow_size(out_benign_flow_sizes[i], out_benign_flow_duration[i], out_mal_flow_sizes[i], out_mal_flow_duration[i], "output", file_name, i)

def get_avg_input_stats(device_obj, mal_flows):
    # rates = []
    rate = 0
    pkt_rate = 0
    size = 0
    benign_flow_sizes = []
    benign_flow_duration = []
    # duration = 0
    flows = 0
    mal_flow_sizes = []
    mal_flow_duration = []
    for flow in device_obj.input_flow_stats:
        if flow not in mal_flows:
            rate += device_obj.input_flow_stats[flow]['byte rate']
            pkt_rate += device_obj.input_flow_stats[flow]["pkt rate"]
            # rates.append(device_obj.input_flow_stats[flow]['byte rate'])
            # duration += device_obj.input_flow_stats[flow]['duration']
            size += device_obj.input_flow_stats[flow]["size"]
            benign_flow_sizes.append(device_obj.input_flow_stats[flow]['size'])
            benign_flow_duration.append(device_obj.input_flow_stats[flow]['duration'])
        elif flow in mal_flows:
            mal_flow_sizes.append(device_obj.input_flow_stats[flow]['size'])
            mal_flow_duration.append(device_obj.input_flow_stats[flow]['duration'])
        if device_obj.input_flow_stats[flow]['size'] > 0:
            flows += 1
            # print("in flow size over zero:", device_obj.input_flow_stats[flow]['size'])
            # print("flow id", flow)
    # print(flows)
    # print(len(device_obj.input_flow_stats.keys()))
    # print(size)
    return {
        "avg_rate": rate/flows,
        "pkt_rate": pkt_rate / flows,
        "flows": flows,
        "size": size,
        "mal_flow_sizes": mal_flow_sizes,
        "mal_flow_duration": mal_flow_duration,
        "benign_flow_sizes": benign_flow_sizes,
        "benign_flow_duration": benign_flow_duration
    }
    # print("flows:", flows, ", keys:", len(device_obj.input_flow_stats.keys()))
    # print("size method", (size/duration)/ flows)

def get_avg_output_stats(device_obj, mal_flows):
    rate = 0
    flows = 0
    pkt_rate = 0
    size = 0
    benign_flow_sizes = []
    benign_flow_duration = []
    mal_flow_sizes = []
    mal_flow_duration = []
    for flow in device_obj.output_flow_stats:
        flows += 1
        if flow not in mal_flows:
            pkt_rate += device_obj.output_flow_stats[flow]["pkt rate"]
            rate += device_obj.output_flow_stats[flow]['byte rate']
            size += device_obj.output_flow_stats[flow]["size"]
            benign_flow_sizes.append(device_obj.output_flow_stats[flow]['size'])
            benign_flow_duration.append(device_obj.output_flow_stats[flow]['duration'])
        elif flow in mal_flows:
            mal_flow_sizes.append(device_obj.output_flow_stats[flow]['size'])
            mal_flow_duration.append(device_obj.output_flow_stats[flow]['duration'])

    return {
        "avg_rate": rate / flows,
        "pkt_rate": pkt_rate / flows,
        "flows": flows,
        "size": size,
        "mal_flow_sizes": mal_flow_sizes,
        "mal_flow_duration": mal_flow_duration,
        "benign_flow_sizes": benign_flow_sizes,
        "benign_flow_duration": benign_flow_duration
    }

def get_input_pkt_sizes(device_obj):
    pkt_sizes = []
    for flow in device_obj.flows['incoming']:
        for pkt in device_obj.flows['incoming'][flow]:
            if pkt['protocol'] == "TCP":
                pkt_sizes.append(pkt['tcp_data']['payload_len'])
            elif pkt['protocol'] == "UDP":
                pkt_sizes.append(pkt['udp_data']['payload_len'])
            elif pkt['protocol'] == "ICMP":
                pkt_sizes.append(pkt['ICMP']['payload_len'])
            else:
                pkt_sizes.append(pkt['payload_len'])
    return pkt_sizes

def get_output_pkt_sizes(device_obj):
    pkt_sizes = []
    for flow in device_obj.flows['outgoing']:
        for pkt in device_obj.flows['outgoing'][flow]:
            if pkt['protocol'] == "TCP":
                pkt_sizes.append(pkt['tcp_data']['payload_len'])
            elif pkt['protocol'] == "UDP":
                pkt_sizes.append(pkt['udp_data']['payload_len'])
            elif pkt['protocol'] == "ICMP":
                pkt_sizes.append(pkt['ICMP']['payload_len'])
            else:
                pkt_sizes.append(pkt['payload_len'])

    return pkt_sizes

def get_input_jitter(device_obj):
    jitter = []
    for flow in device_obj.flows['incoming']:
        flow_jitter = []
        flow_traffic = device_obj.flows['incoming'][flow]
        if len(flow_traffic) > 1:
            for i in range(0, len(flow_traffic)-1, 1):
                try:
                    assert flow_traffic[i+1]['relative_timestamp'].total_seconds() > flow_traffic[i]['relative_timestamp'].total_seconds()
                    # assert flow_traffic[i+1]['ordinal'] > flow_traffic[i]['ordinal']
                    flow_jitter.append(flow_traffic[i+1]['relative_timestamp'].total_seconds() - flow_traffic[i]['relative_timestamp'].total_seconds())
                except AssertionError:
                    print("second packet count:", flow_traffic[i+1]['relative_timestamp'].total_seconds())
                    print("first packet count:", flow_traffic[i]['relative_timestamp'].total_seconds())
                    print("---------------------------------------------")
        jitter.append(np.average(flow_jitter))
    print(jitter)


def analyse_pkt_order(device_obj, direction):
    order = {}
    flows_to_analyse = []
    for flow in device_obj.flows[direction]:
        order[flow] = []
        pkt_list = device_obj.flows[direction][flow]
        for pkt in range(0,len(pkt_list)-1):
            order[flow].append((pkt_list[pkt]['ordinal'], pkt_list[pkt]['relative_timestamp'].total_seconds()))
            if pkt_list[pkt+1]['relative_timestamp'] < pkt_list[pkt]['relative_timestamp']:
                print("flow tuple:",flow)
                print("second pkt count:", pkt_list[pkt+1]['ordinal'], " relative_time:", pkt_list[pkt+1]['relative_timestamp'])
                print("first pkt count:", pkt_list[pkt]['ordinal'], " relative_time:", pkt_list[pkt]['relative_timestamp'])
                flows_to_analyse.append(flow)
    # for flow in flows_to_analyse:
    #     print("------------------------")
    #     print(order[flow])
    #     print("------------------------")


def pkt_size_cdf(input_pkt_sizes, output_pkt_sizes, file_name):
    input_pkt_sizes_sorted = sorted(input_pkt_sizes)
    output_pkt_sizes_sorted = sorted(output_pkt_sizes)
    print(output_pkt_sizes_sorted)
    input_p = np.arange(1, len(input_pkt_sizes)+1) / len(input_pkt_sizes)
    output_p = np.arange(1, len(output_pkt_sizes)+1) / len(output_pkt_sizes)

    # plot the cdf
    fig = plt.figure()
    ax = fig.add_subplot(1, 1, 1)
    ax.plot(input_pkt_sizes_sorted, input_p, label='input packets')
    ax.plot(output_pkt_sizes_sorted, output_p, label='output packets')

    ax.set_xlabel("Packet size (bytes)")
    ax.set_ylabel("CDF")
    plt.legend(loc='best')
    file_name = file_name + "/pkt_size_cdf.png"
    plt.savefig(file_name)
    plt.show()

def plot(x,y, file_name):
    fig = plt.figure()
    ax = fig.add_subplot(1, 1, 1)
    ax.plot(x, y, label= "device traffic")
    ax.set_ylabel("traffic size (MB)")
    ax.set_xlabel("Time (days)")
    file_name = file_name + "/devicetraffic.png"
    plt.legend(loc='best')
    plt.savefig(file_name)
    plt.show()

def plot_flow_direction(time, input, output, plot_style, file_name):
    fig = plt.figure()
    ax = fig.add_subplot(1, 1, 1)
    ax.plot(time, input, label="input flows")
    ax.plot(time, output, label="output flows")
    if plot_style == "byte_rate":
        file_name = file_name + "/flowdirectionbyterate.png"
        ax.set_ylabel("byte rate (KB)")
    elif plot_style == "pkt_rate":
        file_name = file_name + "/flowdirectionpktrate.png"
        ax.set_ylabel("average packet rate")
    elif plot_style == "size":
        ax.set_ylabel("traffic size (MB)")
        file_name = file_name + "/flowdirectionsize.png"
    elif plot_style == "flows":
        ax.set_ylabel("Number of flows")
    ax.set_xlabel("Time (days)")
    plt.legend(loc='best')
    plt.savefig(file_name)
    plt.show()

def plot_input_flow_graph(time,input, file_name):
    fig = plt.figure()
    ax = fig.add_subplot(1,1,1)
    file_name = file_name + "/inputtraffic.png"
    in_kb = []
    for value in input:
        in_kb.append(value * 1000)
    ax.plot(time, in_kb, label="input traffic")
    ax.set_xlabel("Time (days)")
    ax.set_ylabel("Total flow direction size (KB)")
    plt.legend(loc='best')
    plt.savefig(file_name)

def plot_flow_size(benign_size, benign_duration, mal_size, mal_duration, direction, file_name, i):
    fig = plt.figure()
    ax = fig.add_subplot(1,1,1)
    if direction == "input":
        ax.scatter(benign_duration, benign_size, label="benign input flow")
        ax.scatter(mal_duration, mal_size, label="malicious input flow")
    elif direction == "output":
        ax.scatter(benign_size, benign_duration, label="benign output flow")
        ax.scatter(mal_duration, mal_size, label="malicious output flow")
    ax.set_ylabel("flow size (KB)")
    ax.set_xlabel("Flow duration (seconds)")
    plt.legend(loc='best')
    save_name = file_name + direction+ str(i) +"typecompare.png"
    plt.savefig(save_name)
    plt.show()

