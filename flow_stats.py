# from device import DeviceProfile
import matplotlib.pyplot as plt
import numpy as np
from pylab import *
from pathlib import Path
import scipy.stats
from tools import get_ax
""""
This module is for calculating stats and on Device objects

TODO: move below methods into class ModelTrafficBehaviour. 
"""


def model_device_behaviour(device_trafic_objects, dates,mal_flows, save_folder, behaviour_type):
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
    if dates is not None:
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
        if behaviour_type == "benign":
            input_stats = get_avg_input_stats(device_obj, mal_flows=[])
            output_stats = get_avg_output_stats(device_obj, mal_flows=[])
        else:
            input_stats = get_avg_input_stats(device_obj, malicious_flows)
            output_stats = get_avg_output_stats(device_obj, malicious_flows)
        # in_mal_flow_sizes.append(input_stats['mal_flow_sizes'])
        # in_mal_flow_duration.append(input_stats['mal_flow_duration'])
        in_benign_flow_sizes.append(input_stats['benign_flow_sizes'])
        in_benign_flow_duration.append(input_stats['benign_flow_duration'])
        # out_mal_flow_sizes.append(output_stats['mal_flow_sizes'])
        # out_mal_flow_duration.append(output_stats['mal_flow_duration'])
        out_benign_flow_sizes.append(output_stats['benign_flow_sizes'])
        out_benign_flow_duration.append(output_stats['benign_flow_duration'])
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
        input_pkt_sizes.extend(get_input_pkt_sizes(device_obj))
        output_pkt_sizes.extend(get_output_pkt_sizes(device_obj))
        time.append(days)

    # if len(device_trafic_objects) > 0:
    device_name = device_trafic_objects[0].device_name
    file_name = Path(save_folder)
    file_name = str(file_name)
    # file_name = "attack/_" + device_name
    pkt_size_cdf(input_pkt_sizes, output_pkt_sizes, file_name)
    plot_flow_direction(time, avg_input_rate, avg_output_rate, "byte_rate", file_name)
    plot_flow_direction(time, avg_input_pkt_rate, avg_output_pkt_rate, "pkt_rate", file_name)
    plot_flow_direction(time, input_traffic_size, output_traffic_size, "size", file_name)
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


def model_command_traffic(iot_objects, country, device, save_folder):

    commands = ["on", "off", "move", "brightness", "power", "color", "watch", "recording", "photo", "set"]

    controllers = ["alexa", "google", "android", "local"]
    locations = ["lan", "wan"]

    # plots_folder = r"C:\Users\amith\Documents\Uni\Masters\Implementation\commands"
    plots_folder = save_folder
    folder = Path(plots_folder) / country / device
    save_folder = Path(folder)

    run_flow_jitter_comp = False
    attributes = ["input_size","input_pkt_sizes","output_pkt_sizes", "input_duration", "output_size", "output_duration", "input_jitter_sequence", "output_jitter_sequence", "input_jitter_avg", "input_no_of_pkts",
                  "output_jitter_avg", "output_no_of_pkts", "input_flow_jitter_durations", "output_flow_jitter_durations", "input_avg_ttl", "ttl_pkt_no"]
    # command_stats = {command: {"input_size":[], "input_duration":[], "output_pkt_sizes":[], "output_duration":[], "input_jitter":[], "output_jitter":[]} for command in iot_objects}
    command_stats = {command: {controller: {location: {attribute: [] for attribute in attributes} for location in locations} for controller in controllers} for command in commands}
    # command_stats = {command: {controller: None for controller in controllers} for command in commands}
    for command_name in iot_objects:
        if "android" in command_name:
            # Match the command name, location and controller to get keys for storing in command_stats dict
            command = None
            controller = None
            location = None
            for name in commands:
                if name in command_name:
                    command = name
            for contr in controllers:
                if contr in command_name:
                    controller = contr
                # elif command == "power":
                #     controller == "local"
            for loc in locations:
                if re.search(loc, str(command_name)):
                    location = loc
                    # print("regex", loc)
                # else:
                #     location = "physical" #This is for handling google and alexa case as they are sent physically
            if command == "power":
                controller == "local"
                location == "physical"
            for device_obj in iot_objects[command_name]:
                """A device_obj is the devices traffic from a command tracefile"""
                device_obj.update_profile([], [], True) # Calculates the flow stats

                bidirectional_inputs = [flow_tuple[0] for flow_tuple in device_obj.flow_pairs]
                bidirectional_outputs = [flow_tuple [1] for flow_tuple in device_obj.flow_pairs]
                iteration = 1
                if run_flow_jitter_comp is True:
                    for in_flow, out_flow in zip(bidirectional_inputs, bidirectional_outputs):
                        in_pkts, in_jitter = device_obj.get_flow_jitter(device_obj.flows["incoming"][in_flow])
                        out_pkts, out_jitter = device_obj.get_flow_jitter(device_obj.flows["outgoing"][out_flow])
                        save_folder = Path(folder) / command
                        device_obj.compare_command_flow_direction_jitter(in_pkts, in_jitter, out_pkts, out_jitter, str(save_folder), iteration, location)
                        iteration += 1
                input_stats = get_command_input_stats(device_obj, bidirectional_inputs)
                output_stats = get_command_output_stats(device_obj, bidirectional_outputs)
                input_jitter_stats = get_jitter(device_obj, "incoming")
                output_jitter_stats = get_jitter(device_obj, "outgoing")
                # avg_ttl, ttl_pkt_no = get_avg_ttl(device_obj)
                try:
                    command_stats[command][controller][location]['input_jitter_sequence'].extend(input_jitter_stats['jitter_sequence'])
                    command_stats[command][controller][location]['output_jitter_sequence'].extend(output_jitter_stats['jitter_sequence'])
                    command_stats[command][controller][location]['input_jitter_avg'].extend(input_jitter_stats['flow_avg_jitter'])
                    command_stats[command][controller][location]['output_jitter_avg'].extend(output_jitter_stats['flow_avg_jitter'])
                    command_stats[command][controller][location]['input_no_of_pkts'].extend(input_jitter_stats['flow_pkt_no'])
                    command_stats[command][controller][location]['output_no_of_pkts'].extend(output_jitter_stats['flow_pkt_no'])
                    command_stats[command][controller][location]['input_flow_jitter_durations'].extend(input_jitter_stats['flow_durations'])
                    command_stats[command][controller][location]['output_flow_jitter_durations'].extend(output_jitter_stats['flow_durations'])
                    command_stats[command][controller][location]['input_size'].extend(input_stats['flow_sizes'])
                    command_stats[command][controller][location]['output_size'].extend(output_stats['flow_sizes'])
                    command_stats[command][controller][location]['input_duration'].extend(input_stats['flow_duration'])
                    command_stats[command][controller][location]['output_duration'].extend(output_stats['flow_duration'])
                    command_stats[command][controller][location]['input_pkt_sizes'].extend(get_input_pkt_sizes(device_obj))
                    command_stats[command][controller][location]['output_pkt_sizes'].extend(get_output_pkt_sizes(device_obj))
                    # command_stats[command][controller][location]['input_avg_ttl'].extend(avg_ttl)
                    # command_stats[command][controller][location]['ttl_pkt_no'].extend(ttl_pkt_no)
                except KeyError as e:
                    print("key error controller", controller)
                    print("key error command", command)
                    print(e)

    # save_folder = str(save_folder)

    plot_command_flows(command_stats, command='on', file=save_folder)
    plot_command_flows(command_stats, command='off', file=save_folder)


    def plot_graphs():
        for command in command_stats:
            if len(command_stats[command]['android']['lan']) > 0 or len(command_stats[command]['android']['wan']) > 0:
                # compare_command_location_ttl(command_stats, command, save_folder)
                # compare_command_location_ttl(command_stats, 'off', save_folder)
                # plot_command_location_jitter(command_stats, command=command, controller = "android", plot_type="pkt_no", save_folder=save_folder)
            # plot_command_location_jitter(command_stats, command="off", controller="android",plot_type="pkt_no" ,save_folder=save_folder)
                # plot_command_location_jitter(command_stats, command=command, controller="android", plot_type="flow_duration",
            #                              save_folder=save_folder)
            # plot_command_location_jitter(command_stats, command="off", controller="android", plot_type="flow_duration",
            #                              save_folder=save_folder)

                plot_command_flows(command_stats, command=command, file=save_folder)
            # plot_command_flows(command_stats, command='off', file=save_folder)
        # plot_command_flows(command_stats, commands=power, name="power", file=save_folder)
        #         plot_command_jitter_cdf(command_stats, command,save_folder)
        #         plot_command_pkt_size_cdf(command_stats,command ,save_folder)

        compare_command_inputs(command_stats, save_folder)
            # pkt_size_cdf(command_stats, 'on', save_folder)
        # pkt_size_cdf(command_stats["alexa_on"]['input_jitter'], command_stats['alexa_on']['output_jitter'], save_folder)

    # plot_graphs()

def plot_command_jitter_cdf(command_stats, command,save_folder):
    """Compares the jitter of remote and local commands"""
    ax = get_ax()
    locations = ['lan', 'wan']
    for location in locations:
        # if "on" in command and "alexa" not in command and "google" not in command:
        command_jitter_values = sorted(command_stats[command]['android'][location]['input_jitter_sequence'])
        command_jitter_cdf = np.arange(1, len(command_jitter_values) + 1) / len(command_jitter_values)
        label = None
        if "lan" in location:
            label = "lan"
        elif "wan" in location:
            label = "wan"
        ax.plot(command_jitter_values, command_jitter_cdf, label=label)
    # command_response_jitter = sorted(command_stats[command]['output_jitter'])

        # command_response_cdf = np.arange(1, len(command_response_jitter) + 1) / len(command_response_jitter)

    ax.set_xlabel("jitter (ms)")
    ax.set_ylabel("CDF")
    ax.set_title(command + ' input traffic jitter')
    # ax.plot(command_jitter_values, command_jitter_cdf, label='command jitter')
    # ax.plot(command_response_jitter, command_response_cdf, label='response jitter')
    plt.legend(loc='best')
    save_file = Path(save_folder) / command
    plt.savefig(str(save_file) +"jittercdf.png")
    plt.show()

def get_jitter(device_obj, direction):
    # flow_jitter = {flow: [] for flow in device_obj.flows[direction]}
    jitter_info = {
        "jitter_sequence": [], #all jitter values across all flows in the device_obj
        'flow_avg_jitter': [], #average jitter of each flow
        'flow_pkt_no': [], #number of packets in each flow
        'flow_durations': []
    }

    for flow in device_obj.flows[direction]:
        # flow_jitter[flow] = []
        flow_jitter = []
        pkt_no = []
        flow_traffic = device_obj.flows[direction][flow]
        if len(flow_traffic) > 1:
            for i in range(0, len(flow_traffic)-1, 1):
                try:
                    assert flow_traffic[i+1]['relative_timestamp'] > flow_traffic[i]['relative_timestamp']
                    # assert flow_traffic[i+1]['ordinal'] > flow_traffic[i]['ordinal']
                    jitter_info['jitter_sequence'].append((flow_traffic[i+1]['relative_timestamp'] - flow_traffic[i]['relative_timestamp']))
                    flow_jitter.append((flow_traffic[i+1]['relative_timestamp'] - flow_traffic[i]['relative_timestamp']))
                    pkt_no.append(i)
                except AssertionError:
                    print("second packet count:", flow_traffic[i+1]['relative_timestamp'])
                    print("first packet count:", flow_traffic[i]['relative_timestamp'])
                    print("---------------------------------------------")
            jitter_info['flow_avg_jitter'].append(average(flow_jitter))
            jitter_info['flow_pkt_no'].append(len(flow_traffic))
            jitter_info['flow_durations'].append(flow_traffic[-1]['relative_timestamp'] - flow_traffic[0]['relative_timestamp'])

        # ax = get_ax()
        # ax.plot(pkt_no, flow_jitter)
        # ax.set_xlabel('pkt number')
        # ax.set_ylabel('jitter (ms)')
        # if direction == "incoming":
        #     plt.savefig("commandflowjitter.png")
        # else:
        #     plt.savefig("responseflowjitter.png")
    # if direction == "incoming":
    #     if label == "android":
    #         print(direction,":",jitter)

    return jitter_info

def plot_command_flows(command_stats, command, file):
    """Plots command flow duration and size according to the direction of the command flow (input and output)"""
    fig = plt.figure()
    ax = fig.add_subplot(1,1,1)
    print(command_stats[command]['android']['lan'])
    ax.scatter(command_stats[command]['android']['lan']['input_duration'], command_stats[command]['android']['lan']['input_size'],
               label="lan input flow", color='b')
    ax.scatter(command_stats[command]['android']['lan']['output_duration'], command_stats[command]['android']['lan']['output_size'],
               label= "lan output flow", color='g')
    ax.scatter(command_stats[command]['android']['wan']['input_duration'], command_stats[command]['android']['wan']['input_size'],
               label="wan input flow", color='r')
    ax.scatter(command_stats[command]['android']['wan']['output_duration'], command_stats[command]['android']['wan']['output_size'],
               label= "wan output flow", color='y')
    ax.set_ylabel("Flow size (bytes)")
    ax.set_xlabel("Flow duration (seconds)")
    ax.set_title(command + ' command')
    for item in ([ax.title, ax.xaxis.label,ax.yaxis.label] +
                 ax.get_xticklabels() + ax.get_yticklabels()):
        item.set_fontsize(14.5)
    file = Path(file) / command
    file = str(file) + "flowsize.png"
    plt.legend(loc='best')
    plt.savefig(file)
    plt.show()


def get_avg_ttl(device_obj):
    avg_ttl = []
    no_of_pkts = []
    for flow in device_obj.flows["incoming"]:
        ttl_values = []
        if len(device_obj.flows['incoming'][flow]) > 1:
            for pkt in device_obj.flows["incoming"][flow]:
                ttl_values.append(pkt['ttl'])
            avg_ttl.append(average(ttl_values))
            no_of_pkts.append(len(device_obj.flows['incoming'][flow]))

    return avg_ttl, no_of_pkts

def compare_command_location_ttl(command_stats, command,save_folder):
    ax = get_ax()
    ax.scatter(command_stats[command]['android']['lan']['ttl_pkt_no'],
            command_stats[command]['android']['lan']['input_avg_ttl'], label='lan input flow')
    ax.scatter(command_stats[command]['android']['wan']['ttl_pkt_no'],
            command_stats[command]['android']['wan']['input_avg_ttl'], label='wan input flow')
    ax.set_ylabel('TTL')
    ax.set_xlabel('Number of packets')
    ax.set_title("Comparison of command location TTL values (input)")
    file = save_folder / command
    save_file = str(file) + "compare_command_location_ttl.png"
    plt.legend(loc='best')
    plt.savefig(save_file)

def plot_command_pkt_size_cdf(command_stats, command, save_folder):
    ax = get_ax()
    locations = ['lan', 'wan']
    for location in locations:
        pkt_sizes = sorted(command_stats[command]['android'][location]["input_pkt_sizes"])
        pkt_sizes_cdf = np.arange(1, len(pkt_sizes) + 1) / len(pkt_sizes)
        label = None
        if "lan" in location:
            label = "lan"
        elif "wan" in location:
            label = "wan"
        ax.plot(pkt_sizes, pkt_sizes_cdf, label=label + ' input packets')

    ax.set_xlabel("Packet size (bytes)")
    ax.set_ylabel("CDF")
    ax.set_title(command + " packet size cdf")
    # ax.plot(command_jitter_values, command_jitter_cdf, label='command jitter')
    # ax.plot(command_response_jitter, command_response_cdf, label='response jitter')
    plt.legend(loc='best')
    save_file = Path(save_folder) / command
    plt.savefig(str(save_file) + "pktsizecdf.png")
    plt.show()

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
            # rates.append(device_obj.input_flow_stats[flow]['byte rate'])
            # duration += device_obj.input_flow_stats[flow]['duration']
            if device_obj.input_flow_stats[flow]["pkt rate"] is not None:
                rate += device_obj.input_flow_stats[flow]['byte rate']
                pkt_rate += device_obj.input_flow_stats[flow]["pkt rate"]
            else:
                pass
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


    return {
        # "avg_rate": rate/flows,
        # "pkt_rate": pkt_rate / flows,
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
    sizes = []
    benign_flow_sizes = []
    benign_flow_duration = []
    mal_flow_sizes = []
    mal_flow_duration = []
    for flow in device_obj.output_flow_stats:
        flows += 1
        if flow not in mal_flows:
            size += device_obj.output_flow_stats[flow]["size"]
            if type(device_obj.output_flow_stats[flow]["pkt rate"]) is not None:
                # pkt_rate += device_obj.output_flow_stats[flow]["pkt rate"]
                rate += device_obj.output_flow_stats[flow]['byte rate']
            else:
                pass
            benign_flow_sizes.append(device_obj.output_flow_stats[flow]['size'])
            benign_flow_duration.append(device_obj.output_flow_stats[flow]['duration'])
        elif flow in mal_flows:
            mal_flow_sizes.append(device_obj.output_flow_stats[flow]['size'])
            mal_flow_duration.append(device_obj.output_flow_stats[flow]['duration'])

    return {
        # "avg_rate": rate / flows,
        # "pkt_rate": pkt_rate / flows,
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

def get_command_input_stats(device_obj, flow_pairs):
    rate = 0
    total_traffic_size = 0
    sizes = []
    flow_sizes = []
    flow_duration = []
    no_of_flows = 0
    for flow in device_obj.input_flow_stats:
        if flow in flow_pairs:
            no_of_flows += 1
            total_traffic_size += device_obj.input_flow_stats[flow]["size"]
            # rate += device_obj.input_flow_stats[flow]['byte rate']
            flow_sizes.append(device_obj.input_flow_stats[flow]['size'])
            flow_duration.append(device_obj.input_flow_stats[flow]['duration'])


    return {
        "flows": no_of_flows,
        "size": total_traffic_size,
        # "byte_rate": rate / no_of_flows,
        "flow_sizes": flow_sizes,
        "flow_duration": flow_duration
    }

def get_command_output_stats(device_obj, flow_pairs):
    rate = 0
    total_traffic_size = 0
    size = 0
    sizes = []
    flow_sizes = []
    flow_duration = []
    no_of_flows = 0
    for flow in device_obj.output_flow_stats:
        if flow in flow_pairs:
            no_of_flows += 1
            total_traffic_size += device_obj.output_flow_stats[flow]["size"]
            # rate += device_obj.output_flow_stats[flow]['byte rate']
            flow_sizes.append(device_obj.output_flow_stats[flow]['size'])
            flow_duration.append(device_obj.output_flow_stats[flow]['duration'])

    return {
        "flows": no_of_flows,
        "size": total_traffic_size,
        # "byte_rate": rate / no_of_flows,
        "flow_sizes": flow_sizes,
        "flow_duration": flow_duration
    }

def analyse_pkt_order(device_obj, direction):
    order = {}
    flows_to_analyse = []
    for flow in device_obj.flows[direction]:
        order[flow] = []
        pkt_list = device_obj.flows[direction][flow]
        for pkt in range(0,len(pkt_list)-1):
            order[flow].append((pkt_list[pkt]['ordinal'], pkt_list[pkt]['relative_timestamp']))
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
    ax = get_ax()
    ax.plot(input_pkt_sizes_sorted, input_p, label='input packets')
    ax.plot(output_pkt_sizes_sorted, output_p, label='output packets')

    ax.set_xlabel("Packet size (bytes)")
    ax.set_ylabel("CDF")
    plt.legend(loc='best')
    file_name = str(file_name) + "/pkt_size_cdf.png"
    plt.savefig(file_name)
    plt.show()

def plot(x,y, file_name):
    fig = plt.figure()
    ax = fig.add_subplot(1, 1, 1)
    ax.plot(x, y, label= "device traffic")
    ax.set_ylabel("traffic size (MB)")
    ax.set_xlabel("Time (days)")
    file_name = str(file_name) + "/devicetraffic.png"
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
    ax = fig.add_subplot(1, 1, 1)
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
    """ Plots scatter graph of flows according to flow size and duration"""

    fig = plt.figure()
    ax = fig.add_subplot(1, 1, 1)
    if direction == "input":
        ax.scatter(benign_duration, benign_size, label="benign input flow")
        ax.scatter(mal_duration, mal_size, label="malicious input flow")
    elif direction == "output":
        ax.scatter(benign_size, benign_duration, label="benign output flow")
        ax.scatter(mal_duration, mal_size, label="malicious output flow")
    ax.set_ylabel("flow size (KB)")
    ax.set_xlabel("Flow duration (seconds)")
    plt.legend(loc='best')
    save_name = file_name + direction + str(i) + "typecompare.png"
    plt.savefig(save_name)
    plt.show()

def plot_command_location_jitter(command_stats, command, controller, plot_type, save_folder):
    """This function plots the jitter of commands based on their locations. Plots all instances or an average of all instances"""
    ax = get_ax()
    if plot_type == "pkt_no":
        # x axis is number of packets in flow
        lan_input_x = command_stats[command][controller]['lan']["input_no_of_pkts"]
        lan_output_x = command_stats[command][controller]['lan']["output_no_of_pkts"]
        wan_input_x = command_stats[command][controller]['wan']["input_no_of_pkts"]
        wan_output_x = command_stats[command][controller]['wan']["output_no_of_pkts"]
        ax.set_xlabel("Number of packets")
    elif plot_type == "flow_duration":
        # x axis is flow duration time
        lan_input_x = command_stats[command][controller]['lan']["input_flow_jitter_durations"]
        lan_output_x = command_stats[command][controller]['lan']["output_flow_jitter_durations"]
        wan_input_x = command_stats[command][controller]['wan']["input_flow_jitter_durations"]
        wan_output_x = command_stats[command][controller]['wan']["output_flow_jitter_durations"]
        ax.set_xlabel("Flow duration (s)")

    ax.scatter(lan_input_x, command_stats[command][controller]['lan']['input_jitter_avg'], label="lan input", color='b')
    ax.scatter(lan_output_x, command_stats[command][controller]['lan']['output_jitter_avg'], label="lan output", color='y')
    ax.scatter(wan_input_x, command_stats[command][controller]['wan']['input_jitter_avg'], label="wan input", color='r')
    ax.scatter(wan_output_x, command_stats[command][controller]['wan']['output_jitter_avg'], label="wan output", color='g')

    ax.set_ylabel("Average jitter of flow (ms)")
    plt.legend(loc='best')
    save_path = Path(save_folder) / command
    plt.savefig(str(save_path) +"androidlocation"+ plot_type +"jitterduration.png")
    plt.show()
    print(command, controller,"location jitter plotted")

def compare_command_inputs(command_stats, save_folder):
    ax = get_ax()
    ax.set_ylabel("Flow size (bytes)")
    ax.set_xlabel("Flow duration (seconds)")
    ax.set_title("Command type flow characteristics")
    for command in command_stats:
        if len(command_stats[command]['android']['lan']) > 0 or len(command_stats[command]['android']['wan']) > 0:
            for location in command_stats[command]['android']:
                label = command+' '+location+ " flow"
                ax.scatter(command_stats[command]['android'][location]['input_duration'], command_stats[command]['android'][location]['input_size'], label=label)
    plt.legend(loc='best')
    plt.savefig(str(save_folder)+"commandinputflows.png")
    print('compare command inputs plotted')

