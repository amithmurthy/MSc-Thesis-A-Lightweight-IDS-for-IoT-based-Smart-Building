from io import FileIO
from packet_level_signature import *
from trace_filtering import *
from network import NetworkTrace
import threading
from pathlib import Path
from flow_stats import *
import klepto as kl
import os
from preprocess import ModelDevice

"""
This file controls the filtering and analysis process 

1. Control both network analysis and device analysis
2. Control the graphs plotted
Parse packets and then pickle network object
"""
iot = ["Smart Things", "Amazon Echo", "Netatmo Welcom", "TP-Link Day Night Cloud camera", "Samsung SmartCam", "Dropcam",
            "Insteon Camera", "Withings Smart Baby Monitor",
            "Belkin Wemo switch", "TP-Link Smart plug", "iHome", "Belkin wemo motion sensor", "NEST Protect smoke alarm",
            "Netatmo weather station", "Withings Smart scale",
            "Blipcare Blood Pressure meter", "Withings Aura smart sleep sensor", "Light Bulbs LiFX Smart Bulb",
            "Triby Speaker", "PIX-STAR Photo-frame",
            "HP Printer", "Samsung Galaxy Tab", "Nest Dropcam", "TPLink Router Bridge LAN (Gateway)"]


infected_devices = ["TP-Link Smart plug", "Netatmo Welcom", "Huebulb", "iHome", "Belkin Wemo switch","Belkin wemo motion sensor", "Samsung SmartCam", "Light Bulbs LiFX Smart Bulb"]

remianing = ["Belkin Wemo switch","Belkin wemo motion sensor", "Samsung SmartCam", "Light Bulbs LiFX Smart Bulb"]
device_filter = ["Netatmo Welcom"]
device_events = {
    "tplink-plug": {
        'alexa_off': "2019-05-04_15_27_41.24s",
        "alexa_on": "2019-04-28_15_52_32.23s",
        "power": "2019-04-26_12_41_34.198s"},
    "ring-doorbell": {
        'alexa_stop': "2019-04-26_17_30_24.22s",
        'alexa_watch': "2019-04-26_18_46_31.22s",
        'local_move': "2019-04-26_15_52_31.101s",
        'android_wan_watch': "2019-04-29_10_54_20.47s",
        "android_lan_watch": "2019-04-28_15_44_57.47s",
        'power': "2019-04-26_12_23_33.215s"}
}

def get_pcaps(dataset):

    dir_path = Path(dataset)
    traces = dir_path.glob('*.pcap')
    for path in dir_path.rglob('*.pcap'):
        yield path
        # print(path.name)
    # paths = []
    # for path in dir_path.rglob('*.pcap'):
    #     paths.append(path)
    # return paths
    # print(file_count)
    # return file_list

def get_file_list(dataset):
    dir_path = Path(dataset)
    file_list = []
    for path in dir_path.iterdir():
        if "pcap" in path.name:
            continue
        else:
            file_list.append(path.name)
    return file_list

def analyse_dataset(dataset, save_path,malicious_pkts,benign_pkts):
    large_attack_files = ["18-06-01", "18-06-02", "18-06-03", "18-06-04", "18-06-05"]
    processed_files = ["18-06-11", "18-06-12", "18-06-13", "18-06-14", "18-06-15", "18-06-16"]

    for file in get_pcaps(dataset):
        print(file)
        # if str(file)[-13:-5] in processed_files:
        #     continue
        traffic_file = NetworkTrace(file)
        analyse_pcap(traffic_file, FileIO(file))
        print("creating device objects")
        devices = get_device_objects(traffic_file, malicious_pkts, benign_pkts)
        print("saving traffic")
        save_traffic(traffic_file, save_path, devices)
        # processed_files.append(str(file)[-13:-5])

def analyse_device_events(file_path, device):
    # this is where the pcaps are stored
    dir_path = Path(file_path) / device
    command_folders = Path(dir_path)
    country = str(file_path)[-2:] # either the us or uk depends on the file path
    iot_devices = get_iot_devices(country)
    path = r"C:\Users\amith\Documents\Uni\Masters\Implementation\commands"
    def create_folders():
        for obj in iot_devices:
            path = Path(path) / country / obj
            folder = Path(path)
            if folder.is_dir():
                pass
            else:
                folder.mkdir()
    iot_objects = {}
    non_iot_objects = {}
    for command in command_folders.iterdir():
        # if file.name in device_events[device]:
            # print(file.name)
        iot_objects[command.name] = []
        non_iot_objects[command.name] = []
        count = 0
        for pcap in command.iterdir():
            # print(pcap.name)
            # if pcap.name[0:-5] in device_events[device][file.name]:
            if count > 5:
                break
            print("analysing pcap", pcap.name)
            traffic_file = NetworkTrace(pcap, devices=iot_devices)
            analyse_pcap(traffic_file, FileIO(pcap), ttl = "ttl")
            print("creating device objs from pcap")
            device_list = get_device_objects(traffic_file, [], [])
            for device_obj in device_list:
                if device_obj.mac_address == iot_devices[device]:
                    iot_objects[command.name].append(device_obj)
                else:
                    non_iot_objects[command.name].append(device_obj)
    # print("iot_objects:",iot_objects)

    event_traffic = get_reorganised_command_traffic_dict(iot_objects)
    # device_command_signature = PacketLevelSignature(event_traffic)
    # device_command_signature.cluster_event_traffic("on")
    def make_command_plot_folders():
        for command_name in event_traffic:
            # Saving graphs in appropriate folders i.e. accroding to the command
            if len(event_traffic[command_name]['lan']) > 0 or len(event_traffic[command_name]['wan']) > 0:
                save_graph_path = Path(path) / country / device / command_name
                save_folder = Path(save_graph_path)
                if save_folder.is_dir():
                    pass
                else:
                    save_folder.mkdir()
                # plot_command_traffic = model_device_behaviour(device_trafic_objects=iot_objects[command_name], dates=None, mal_flows={}, save_folder=save_folder, behaviour_type="benign")
                # if plot_command_traffic:
                #     print(plot_command_traffic)
                #     continue
    # make_command_plot_folders()
    model_command_traffic(iot_objects, country, device, path)

def preprocess_device_traffic(device_filter, data_type):
    traffic = processed_attack_traffic if data_type == 'attack' else processed_benign_traffic
    network_instances = unpickle_network_trace_and_device_obj(traffic, devices=device_filter)
    # attack_network_instances = unpickle_network_trace_and_device_obj(processed_attack_traffic, devices=device_filter)
    device_traffic = []
    for network_obj in network_instances:
        for device_obj in network_instances[network_obj]:
            # if device_obj.device_name not in device_filter:
            #     continue
            device_traffic.append(device_obj)
            device_obj.update_profile([], [], compute_attributes=False)
            device_obj.sort_flow_location(network_obj)
            # device_obj.set_location_direction_rates()

    print('Number of device instances in dataset', len(device_traffic))
    ModelDevice(model_function="preprocess", device_name=device_filter, device_traffic=device_traffic, time_scales=[60, 120, 240], data_type=data_type)

def train_clustering_model(device, feature_set, window, sampling_window):
    """Train and test device clustering model"""
    # ModelDevice(model_function='preprocess', saved_features=True, time_scales=[200,300], device_name=device)
    # ModelDevice(model_function="train", device_name=device, train_type='find_k', feature_set=feature_set, window=window,sampling_window=sampling_window)
    ModelDevice(model_function='train', device_name=device, feature_set=feature_set,window=window,sampling_window=sampling_window)
    ModelDevice(model_function="anomaly_detection", device_name=device, feature_set=feature_set,window=window,sampling_window=sampling_window)
    # ModelDevice(model_function="validate", device_name=device)


def cluster_device_signature(processed_traffic_path):
    """Clusters multiple network traces instead of just one to get a better signature of benign device behaviour"""
    network_instances = unpickle_network_trace_and_device_obj(processed_traffic_path, limit=15, devices=device_filter)
    for network_obj in network_instances:
        for device_obj in network_instances[network_obj]:
            if device_obj.device_name not in device_filter:
                continue
            device_obj.update_profile([],[], False)
            device_obj.set_device_activity()
            device_obj.sort_flow_location(network_obj)
            device_obj.set_location_direction_rates()
            device_obj.cluster_device_signature_features()
        # network_obj.device_signature_plots(network_instances[network_obj])
        network_obj.device_flow_direction_signature(network_instances[network_obj])

def extract_packet_level_signature(device_objs):
    """Takes in all device_objs of a device and calls PacketLevelFeatures"""
    for device_obj in device_objs:
        PacketLevelSignature({},'device', device_obj)

def extract_timestamps(dataset, save_path):
    count = 0
    limit = math.inf
    processed = ['16-09-23']
    for file in get_pcaps(dataset):
        print(file)

        count += 1
        if count > limit:
            break
        if str(file)[-13:-5] in processed:
            continue
        pcap = NetworkTrace(file)
        # Pass in epoch filter and get the ordinal_timestamp dict
        analyse_pcap(pcap, FileIO(file), epoch_filter=True)
        # Save dictionary so it can be unpacked later to modify incorrect timestamp
        save_dir = save_path + '\_' + pcap.file_name + '\_network_info'
        ar = kl.archives.dir_archive(name=save_dir, serialized=True, cached=True, protocol=4)
        try:
            print("saving ordinal_timestamp")
            ar['ordinal_timestamp'] = pcap.ordinal_timestamp
            ar.dump()
            ar.clear()
        except MemoryError:
            print("memory error for ordinal_timestamp dict")
            pass

def modify_timestamp(processed_traffic_path, *files):
    # Cannot unpack all 60 files - not enough memory.
    if files:
        files = files[0]
    else:
        files = get_file_list(processed_traffic_path)

    print('files', len(files))
    # test_file = ['_16-09-23','_16-09-24']

    for file in files:
        print("unpickling", file)
        network_instances = unpickle_network_trace_and_device_obj(processed_traffic_path,extract_timestamp=True, files=file)
        for network_trace in network_instances:
            # print('path', processed_traffic_path + "\_" + network_trace.file_name[-14:-5])
            network_trace.change_device_timestamp(network_instances[network_trace])
            for device in network_instances[network_trace]:
                print('saving devices')
                path = processed_traffic_path + "\_" + network_trace.file_name[-14:-5] + '\_' +device.device_name + "-db"
                shelve_device_traffic(device, path, 'timestamp')

    print("COMPLETED MODIFYING TIMESTAMP BUG")

def compare_attack_and_benign(device_addr,device_name):
    """Plot throughput of attack flows to compare against benign flow types - only for one device """
    malicious_flows = get_malicious_flows(r"C:\Users\amith\Documents\Uni\Masters\Datasets\UNSW\2018\annotations\annotations")
    count = 0
    limit = 1
    for trace_date in malicious_flows[device_addr]:
        count +=1
        if count > limit:
            break
        attack_flows = malicious_flows[device_addr][trace_date]
        print(len(attack_flows))
        ## Unpickle that trace_file date device traffic###
        trace_date_traffic = unpickle_network_trace_and_device_obj(processed_attack_traffic, files=str('_'+ trace_date[2:]), devices=device_name)
        device_obj = list(trace_date_traffic.items())[0][1][0]
        network_obj = list(trace_date_traffic.items())[0][0]
        device_obj.update_profile([],[],True, attack_flows)
        device_obj.sort_flow_location(network_obj)
        device_obj.set_location_direction_rates()
        # device_obj.plot_location_direction_rate()
        # device_obj.plot_flow_type(network_obj.file_name)

def find_first_pkts():

    network_instances = unpickle_network_trace_and_device_obj(processed_attack_traffic, devices="iHome")
    # attack_network_instances = unpickle_network_trace_and_device_obj(processed_attack_traffic, devices=device_filter)
    device_first_pkt = {}

    for network_obj in network_instances:
        for device_obj in network_instances[network_obj]:
            smallest_ordinal = None
            for direction in device_obj.flows:
                for flow in device_obj.flows[direction]:
                    flow_start_ordinal = device_obj.flows[direction][flow][0]['ordinal']
                    if smallest_ordinal is None:
                        smallest_ordinal = flow_start_ordinal
                    else:
                        if flow_start_ordinal < smallest_ordinal:
                            smallest_ordinal = flow_start_ordinal
                        else:
                            continue
            device_first_pkt[network_obj.file_name] = smallest_ordinal

    print(device_first_pkt)

def plot_segregated_traffic(device):
    network_instances = unpickle_network_trace_and_device_obj(processed_benign_traffic, limit=1,devices=device)
    for network_obj in network_instances:
        for device_obj in network_instances[network_obj]:
            device_obj.update_profile([],[],False)
            device_obj.sort_flow_location(network_obj)
            device_obj.set_sampling_rate(5)
            device_obj.set_device_activity()
            device_obj.set_location_direction_rates()
            # device_obj.plot_location_direction_rate(network_obj.file_name)
            # device_obj.plot_location_direction_pkt_rate(network_obj.file_name)
            # device_obj.set_device_activity()


def plot_all_device_signatures(device):
    network_instances = unpickle_network_trace_and_device_obj(processed_benign_2016, limit=3, devices=device)
    for network_obj in network_instances:
        for device_obj in network_instances[network_obj]:
            device_obj.update_profile([], [], False)
            device_obj.sort_flow_location(network_obj)
            device_obj.set_sampling_rate(5)
            device_obj.set_device_activity()
            device_obj.set_location_direction_rates()
            # device_obj.plot_location_direction_rate(network_obj.file_name)
            # device_obj.plot_location_direction_pkt_rate(network_obj.file_name)
            device_obj.set_device_activity()
            device_obj.cluster_device_signature_features(500, "pkt_count")

def device_flow_stats(device):
    network_instances = unpickle_network_trace_and_device_obj(processed_benign_2016, limit=3, devices=device)
    stats = ['avg_pkt_size', 'avg_byte_rate']
    metrics = {
        'local_inputs': {stat: [] for stat in stats},
        'local_outputs': {stat: [] for stat in stats},
        'internet_inputs': {stat: [] for stat in stats},
        'internet_outputs': {stat: [] for stat in stats}
    }
    for network_obj in network_instances:
        for device_obj in network_instances[network_obj]:
            device_obj.update_profile([], [], False)
            device_obj.sort_flow_location(network_obj)
            device_obj.set_sampling_rate(5)
            device_obj.set_device_activity()
            device_obj.set_location_direction_rates()
            # device_obj.plot_location_direction_rate(network_obj.file_name)
            # device_obj.plot_location_direction_pkt_rate(network_obj.file_name)
            device_obj.set_device_activity()
            # device_obj.cluster_device_signature_features(500, "pkt_count")
            values = device_obj.get_avg_flow_byte_rate()
            for flow in values:
                for s in values[flow]:
                    metrics[flow][s].append(values[flow][s])


    avg_stats = {flow:{stat:(sum(metrics[flow][stat]) / len(metrics[flow][stat])) for stat in stats} for flow in metrics}
    # print(metrics)
    # print(avg_stats)
    # for flow in metrics:
    #     for s in metrics[flow]:
    #         avg_stats[flow][s] = sum(metrics)
    p = Path(r'C:\Users\amith\Documents\Uni\Masters\results\device_type\traffic_stats')
    import csv
    with open(str(p/ (device + ".csv")), 'w') as fd:
        dw = csv.writer(fd)
        for key, value in avg_stats.items():
            dw.writerow([key, value])



def main():
    process_moniotr_file_path = r"C:\Users\amith\Documents\Uni\Masters\processed-traffic\moniotr"
    northeastern_dataset_uk = r"D:\Mon(IoT)r\iot-data\uk"
    # tp_benign_plot()
    # fs_fpr_plot()
    # devices = get_iot_devices("uk")
    # for device in devices:
        # if device != "yi-camera" or device != "tplink-plug":
        # analyse_device_events(northeastern_dataset_uk, device)
    # analyse_device_events(northeastern_dataset_uk, "tplink-plug")

    # analyse_device_events(dataset_file_paths['tplink-plug'], "tplink-plug")
    # analyse_device_events(dataset_file_paths['ring-doorbell'], "ring-doorbell")
    # parse_dataset()
    dataset1 = r"C:\Users\amith\Documents\Uni\Masters\Datasets\UNSW\IoT Traces\Extracted"
    attack_dataset = r"C:\Users\amith\Documents\Uni\Masters\Datasets\UNSW\2018\Attack Data"
    benign_dataset = r"C:\Users\amith\Documents\Uni\Masters\Datasets\UNSW\2018\to-do"
    # attack_file = "18-10-20.pcap"
    # benign_file = "18-10-29.pcap"
    test_file = "16-09-23.pcap"

    # analyse_pcap(pcap_file, "16-09-23.pcap")
    malicious_pkts = []
    benign_pkts = []
    pkt_rmse = []
    # with open('results.pickle', 'rb') as pickle_fd:
    #     phi = pickle.load(pickle_fd)
    #     malicious_pkts = pickle.load(pickle_fd)
    #     benign_pkts = pickle.load(pickle_fd)
    #     pkt_rmse = pickle.load(pickle_fd)

    global processed_attack_traffic
    global processed_benign_traffic
    global processed_benign_2016
    # processed_attack_traffic = r"C:\Users\amith\Documents\Uni\Masters\processed-traffic\Attack"
    processed_attack_traffic = r"D:\New back up\Takeout\Drive\UNSW device traffic\Attack"
    processed_benign_traffic = r"C:\Users\amith\Documents\Uni\Masters\processed-traffic\Benign"
    # processed_benign_traffic = r"D:\Benign"
    processed_benign_2016 = r"C:\Users\amith\Documents\Uni\Masters\processed-traffic\2016"
    # plot_segregated_traffic("Belkin wemo motion sensor")
    p = ['iHome', 'TP-Link Smart plug']
    # for i in p:
    #     plot_segregated_traffic(i)
    # plot_segregated_traffic("Netatmo Welcom")
    # new_traffic = r"D:\Benign"
    # analyse_dataset(benign_dataset, processed_attack_traffic, [],[])
    # preprocess_device_traffic("Amazon Echo", 'benign')
    feature_set = ["FS2", "FS3"]
    windows = ['120', '240']
    sampling_rates = ['10', '30', '60']
    d = ["TP-Link Smart plug", "iHome", "Netatmo Welcom", "Samsung SmartCam", "Belkin wemo motion sensor", "Light Bulbs LiFX Smart Bulb"]
    b = "TP-Link Smart plug", "iHome"
    # find_first_pkts()
    n = ["Belkin wemo motion sensor","Netatmo Welcom", "Samsung SmartCam", "Light Bulbs LiFX Smart Bulb"]
    # plot_segregated_traffic("TP-Link Smart plug")

    # plot_segregated_traffic("Belkin wemo motion sensor")
    # for device in d:
    #     for fs in feature_set:
    #         for sliding_window in windows:
    #             for s_rate in sampling_rates:
    #                 train_clustering_model(device, fs, sliding_window, s_rate)

    # train_clustering_model("Samsung SmartCam", "FS3", '120', '60')
    # train_clustering_model("Belkin Wemo switch", "FS3", '120', '30')
    # train_clustering_model("Belkin Wemo switch", "FS3", '120', '60')
    # train_clustering_model("Netatmo Welcom", "FS3", "120", '30')
    #     train_clustering_model(device, "FS2", "120", "10")
    #     train_clustering_model(device, "FS2", "120", "30")
    #     train_clustering_model(device, "FS2", "120", "60")
    #     train_clustering_model(device, "FS2", "240", "10")
    #     train_clustering_model(device, "FS2", "240", "30")
    #     train_clustering_model(device, "FS2", "240", "60")
    #     train_clustering_model(device, "FS3", "120", "10")
        # train_clustering_model(device, "FS3", "120", "30")
        # train_clustering_model(device, "FS3", "120", "60")
        # train_clustering_model(device, "FS3", "240", "10")
        # train_clustering_model(device, "FS3", "240", "30")
        # train_clustering_model(device, "FS3", "240", "60")
    #     preprocess_device_traffic(device, 'attack')
    # train_clustering_model("iHome", "FS2", '120', '10')
    # for i in d:
    #     for s in sampling_rates:
    #         train_clustering_model(i, "FS3", '120', s)
    # train_clustering_model("TP-Link Smart plug", "FS2", "240", "10")
    # train_clustering_model("Netatmo Welcom", "FS3", "240", "60")
    # train_clustering_model("Belkin wemo motion sensor", "FS2", "120", "10")
    # train_clustering_model("Belkin wemo motion sensor", "FS2", "120", "30")
    # train_clustering_model("Belkin wemo motion sensor", "FS2", "120", "60")

    # extract_timestamps(dataset1, processed_benign_2016)
    # modify_timestamp(processed_benign_2016)
    # analyse_dataset(attack_dataset, processed_attack_traffic, malicious_pkts, benign_pkts)
    # processed = ["Dropcam", "Amazon Echo", "Netatmo Welcom", "TP-Link Day Night Cloud camera", "Samsung SmartCam"]

    # cluster_device_signature(processed_benign_traffic)
    # compare_attack_and_benign("70:ee:50:18:34:43", "Netatmo Welcom")
    dates = ["2018-06-01","2018-06-02", "2018-06-03", "2018-06-04","2018-06-06", "2018-06-07","2018-06-08"]
    # mal_keys = list(malicious_flows.keys())
    all_devices = get_all_devices()
    # for j in all_devices:
    #     plot_all_device_signatures(j)
    # plot_all_device_signatures("NEST Protect smoke alarm")
    device_flow_stats("TP-Link Smart plug")
    # def process_attack_traffic():
    #     for device in infected_devices:
    #         traffic_objects, dates = unpickle_device_objects(processed_attack_trafffic, device)
    #         for date in dates:
    #             # if date in mal_keys:
    #             make_graphs = model_device_behaviour(traffic_objects, date, malicious_flows)
    #             if make_graphs:
    #                 print(make_graphs)
    #                 break

    def process_benign_traffic():
        for device in iot:
            print(device)
            device_objs, network_objs, dates = unpickle_device_objects(processed_benign_traffic, device, "mal")
            # print(x)
            # make_graphs = model_device_behaviour(device_objs,dates , mal_flows={}, save_folder=r"D:", behaviour_type='benign')
            extract_packet_level_signature(device_objs)

    # process_benign_traffic()

    # tp_link_traffic, network_trace = unpickle_device_objects(processed_benign_traffic, "TP-Link Smart plug", "benign")
    # if len(tp_link_traffic) == len(network_trace):
    #     for i in range(0, len(tp_link_traffic)):
    #         tp_link_traffic[i].update_profile([],[])
    #         # tp_link_traffic[i].sort_flow_location(network_trace[i])
    #         tp_link_traffic[i].compare_flow_location_traffic()
    #
    # pcap = NetworkTrace(test_file)
    # thread = threading.Thread(target=analyse_pcap(pcap, test_file, count_limit=100000))
    # thread.start()
    # thread.join()
    # device_objs = get_device_objects(pcap, [], [])
    # for device in device_objs:
    #     device.update_profile([],[])
        # device.sort_flow_location(pcap)
        # device.compare_flow_location_traffic()
    # device_signature_plots(device_objs)

    def compare_sampling_rate():
        p = Path(r'C:\Users\amith\Documents\Uni\Masters\results\device_type\sampling window')
        import pandas as pd
        s = ['10', '30', '60']
        x = ['accuracy', 'fpr', 'avg_detection_rate']
        types = get_device_type('iHome', True)
        model_stats = {device_type: {i: {j: [] for j in s} for i in x} for device_type in types}
        for file in p.iterdir():
            for d in infected_devices:
                if d in file.name:
                    print(file.name)
                    d_type = get_device_type(d)
                    rate = get_s(file.name)
                    data = pd.read_csv(file, header=None)
                    # print('detection_rate',data.iloc[9][1])
                    print('fpr', data.iloc[4][1])
                    print('accuracy', data.iloc[8][1])
                    # print('tpr', data.iloc[6][1])
                    print('----------')
                    model_stats[d_type]['accuracy'][rate].append(data.iloc[8][1])
                    model_stats[d_type]['avg_detection_rate'][rate].append(data.iloc[9][1])
                    model_stats[d_type]['fpr'][rate].append(data.iloc[4][1])
                    # print(accuracy, avg_detection_rate, fpr)
        # print(model_stats['switch'])
        # plot_sampling_impact('accuracy', model_stats, "Accuracy (%)")
        # plot_sampling_impact('fpr', model_stats, "FPR (%)")
        # plot_sampling_impact('avg_detection_rate', model_stats, "Average Detection Rate (%)")

    # compare_sampling_rate()
if __name__ == "__main__":
    main()

    # for device in infected_devices:
    #     path = r"C:\Users\amith\Documents\Uni\Masters\Graphs\Machine Learning"
    #     folder = Path(path) / device
    #     if folder.is_dir():
    #         continue
    #     else:
    #         folder.mkdir()


    # thread1 = threading.Thread(target= save_traffic(pcap_file, file_path, devices))
    # thread2 = threading.Thread(target=create_device_plots(devices,malicious_pkts, benign_pkts))
    # thread1.start()
    # thread2.start()
    # thread1.join()

    # create_device_plots(devices,malicious_pkts, benign_pkts)
    # devices_objs = unpickle_device_objects(file_path, "16-09-23")
    # print(devices_objs)
