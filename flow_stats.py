# from device import DeviceProfile
import matplotlib.pyplot as plt
""""
This module is for calculating stats on Device objects
"""


def model_device_behaviour(device_trafic_objects, mal_flows):
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
    malicious_flows = mal_flows

    for device_obj in device_trafic_objects:
        days += 1
        total_traffic = 0
        device_obj.update_profile([], [])
        input_stats = get_avg_input_stats(device_obj)
        print(input_stats['size'])
        output_stats = get_avg_output_stats(device_obj)
        avg_input_rate.append(input_stats['avg_rate'])
        avg_input_pkt_rate.append(input_stats['pkt_rate'])
        avg_output_rate.append(output_stats['avg_rate'])
        avg_output_pkt_rate.append(output_stats['pkt_rate'])
        input_traffic_size.append(input_stats['size'] / 1000000)
        output_traffic_size.append(output_stats['size'] / 1000000)
        total_traffic += (input_stats['size'] / 1000000) + (output_stats['size'] / 1000000)
        total_traffic_size.append(total_traffic)
        in_flows.append(input_stats['flows'])
        out_flows.append(output_stats['flows'])
        time.append(days)

    device_name = device_trafic_objects[0].device_name
    # file_name = "plots/_" + device_name
    file_name = "attack/_" + device_name
    plot(time, total_traffic_size, file_name)

    plot_flow_direction(time, avg_input_rate, avg_output_rate, "byte_rate", file_name)
    plot_flow_direction(time, avg_input_pkt_rate, avg_output_pkt_rate, "pkt_rate", file_name)
    plot_flow_direction(time, input_traffic_size, output_traffic_size,"size", file_name)
    plot_flow_direction(time, in_flows, out_flows, "flows", file_name)
    plot_input_flow_graph(time, input_traffic_size, file_name)
    return device_name + "done"

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
    flows =0
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


def plot(x,y, file_name):
    fig = plt.figure()
    ax = fig.add_subplot(1, 1, 1)
    ax.plot(x, y, label= "device traffic")
    ax.set_ylabel("traffic rate (MB)")
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
        ax.set_ylabel("traffic size")
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
