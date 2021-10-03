from pathlib import Path
from copy import deepcopy
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
from itertools import chain
from multiprocessing import Pool
import pickle
from tools import *
from attack_annotations import Attacks
"""This class is primarily for visualising feature correlation/analytics"""

class FeatureAnalytics():

    def __init__(self):
        self.feature_data = Path(r"C:\Users\amith\Documents\Uni\Masters\JNCA\features")
        self.saved_traffic = Path(r"C:\Users\amith\Documents\Uni\Masters\JNCA\traffic\processed-traffic")
        self.devices = ["TP-Link Smart plug", "Netatmo Welcom", "Huebulb", "iHome", "Belkin Wemo switch","Belkin wemo motion sensor", "Samsung SmartCam", "Light Bulbs LiFX Smart Bulb"]
        self.flows = ['local_inputs', 'local_outputs', 'internet_inputs', 'internet_outputs']
        self.features = ['byte_count', 'pkt_count', 'byte_mean', 'byte_std', 'pkt_mean', 'pkt_std', 'avg_pkt_size']
        # self.saved_feature_names = ['one_min_byte_count', 'one_min_pkt_count', 'two_min_byte_mean', 'two_min_byte_std', 'two_min_pkt_mean', 'two_min_pkt_std']
        self.benign_traffic_features = {flow: {feature: [] for feature in self.features} for flow in self.flows}
        # self.attack_traffic_features = deepcopy(self.benign_traffic_features)
        self.local_inputs = {
            'mean': [],
            'std': []
        }
        self.local_outputs = {
            'mean': [],
            'std': []
        }
        self.internet_inputs = {
            'mean': [],
            'std': []
        }
        self.internet_outputs = {
            'mean': [],
            'std': []
        }
        attack_rates = ['1pps', '10pps', '100pps']
        self.attack_traffic = {attack_rate: {flow: {'mean': [], 'std': []} for flow in self.flows} for attack_rate in attack_rates}
        self.pickle_path = Path(r"C:\Users\amith\Documents\Uni\Masters\JNCA")
        # self.flow_feature_cdf_plots()

    def parse_benign_device_traffic(self):
        self.parse_dataset(self.devices[0])
        # print(self.internet_inputs)
        self.pickle_feature_stats(self.devices[0]+"benign_traffic.pickle")

    def draw_compare_plots(self):
        flow_label_map = {
            'local_inputs': "Local inputs",
            'local_outputs': "Local outputs",
            'internet_inputs': 'Internet inputs',
            'internet_outputs': 'Internet outputs'
        }

        benign_traffic, attack_traffic = self.load_parsed_pickle(self.devices[0])

        def get_xlabel(feature):
            if feature == 'std':
                return "Standard deviation of bytes over 2 min sliding window"
            else:
                return "Mean byte count over 2 min sliding window"

        def plot_feature_cdf(flow, feature):
            ax = get_ax()
            benign_flow = self.get_cdf_data(benign_traffic[flow], feature)
            attack_flow = self.get_cdf_data(attack_traffic[flow], feature)
            ax.set_ylabel("CDF")
            ax.set_xlabel(get_xlabel(feature))
            ax.plot(benign_flow[0], benign_flow[1],label="Benign "+flow_label_map[flow],color='b')
            ax.plot(attack_flow[0], attack_flow[1], label="Attack "+flow_label_map[flow], color='r')
            plt.legend(loc='best', fontsize=15)
            plt.show()
            # plt.savefig(str(self.feature_data / (flow+feature+".png")))

        # plot_mean('local_inputs', 'mean')
        plot_feature_cdf('local_outputs', 'std')

    def flow_feature_cdf_plots(self, load_data=False):
        if load_data is False:
            if self.parse_dataset():
                self.pickle_feature_stats()
        else:
            self.load_parsed_pickle()
            self.plot_feature_cdf()

    def get_cdf_data(self, flow, feature):
        flow_feature = flow[feature]
        feature_values = sorted(flow_feature)
        feature_value_probability = np.arange(1, len(flow_feature) + 1) / len(flow_feature)
        return feature_values, feature_value_probability

    @staticmethod
    def convert_to_KB(byte_list):
        return [int(x) / 1000 for x in byte_list]

    def plot_feature_cdf(self):
        # local_inputs_mean = self.get_cdf_data(self.local_inputs, 'std')
        # local_outputs_mean = self.get_cdf_data(self.local_outputs, 'std')
        internet_inputs_mean = self.get_cdf_data(self.internet_inputs, 'std')
        internet_outputs_mean = self.get_cdf_data(self.internet_outputs, 'std')
        ax = get_ax()
        ax.set_ylabel("CDF")
        ax.set_xlabel("Standard deviation of bytes in flow")
        # ax.plot(local_inputs_mean[0], local_inputs_mean[1], label= 'Local inputs', color='b')
        # ax.plot(local_outputs_mean[0], local_outputs_mean[1], label='Local outputs', color='r')
        ax.plot(internet_inputs_mean[0], internet_inputs_mean[1], label='Internet inputs')
        ax.plot(internet_outputs_mean[0], internet_outputs_mean[1], label='Internet outputs')
        plt.legend(loc='best', fontsize=15)
        plt.show()
        plt.savefig(str(self.feature_data / "local_cdf_plots_std.png"))

    def pickle_feature_stats(self, file_in):
        # save_path = Path(r"C:\Users\amith\Documents\Uni\Masters\JNCA")
        with open(str(self.pickle_path / file_in), 'wb') as pickle_file:
            pickle.dump(self.local_inputs, pickle_file)
            pickle.dump(self.local_outputs, pickle_file)
            pickle.dump(self.internet_inputs, pickle_file)
            pickle.dump(self.internet_outputs, pickle_file)

    def aggregate_flow_feature_data(self, flow, feature_data):
        flow['mean'].extend(feature_data['mean'])
        flow['std'].extend(feature_data['std'])


    def sort_flow_stats(self, device_obj, **kwargs):

        if kwargs:
            flows = kwargs['attack_flows']
        else:
            flows = device_obj.flow_features

        for flow in flows:
            # feature_data = device_obj.flow_features[flow]
            if flow in device_obj.internet_output_flows:
                self.aggregate_flow_feature_data(self.internet_outputs, device_obj.flow_features[flow])
            if flow in device_obj.internet_input_flows:
                self.aggregate_flow_feature_data(self.internet_inputs, device_obj.flow_features[flow])
            if flow in device_obj.local_input_flows:
                self.aggregate_flow_feature_data(self.local_inputs, device_obj.flow_features[flow])
            if flow in device_obj.local_output_flows:
                self.aggregate_flow_feature_data(self.local_outputs, device_obj.flow_features[flow])

    def parse_dataset(self, device):
        benign_database = self.saved_traffic / "Benign"
        for file in benign_database.iterdir():
            benign_traffic = unpickle_network_trace_and_device_obj(str(benign_database), devices=device, files=file.name)
            for network_obj in benign_traffic:
                for device_obj in benign_traffic[network_obj]:
                    if device_obj.device_name == "Belkin wemo motion sensor":
                        continue
                    device_obj.update_profile([], [], False)
                    device_obj.sort_flow_location(network_obj)
                    print("processing", device_obj.device_name)
                    device_obj.get_flow_tuple_features()
                    self.sort_flow_stats(device_obj)
                print("FINISHED FILE PROCESSING")
        print("FINISHED PARSING DATASET")
        # print(len(self.local_inputs['mean']))
        return True

    def load_parsed_pickle(self, device):
        flows = ['local_inputs', 'local_outputs', 'internet_inputs', 'internet_outputs']
        benign_traffic = {flow: None for flow in flows}
        attack_traffic = {flow: None for flow in flows}

        with open(str(self.pickle_path / (device+"benign_traffic.pickle")), 'rb') as pickle_fd:
            benign_traffic['local_inputs'] = pickle.load(pickle_fd)
            benign_traffic['local_outputs'] = pickle.load(pickle_fd)
            benign_traffic['internet_inputs'] = pickle.load(pickle_fd)
            benign_traffic['internet_outputs'] = pickle.load(pickle_fd)

        with open(str(self.pickle_path / (device+"attack_traffic.pickle")), 'rb') as pickle_fd:
            attack_traffic['local_inputs'] = pickle.load(pickle_fd)
            attack_traffic['local_outputs'] = pickle.load(pickle_fd)
            attack_traffic['internet_inputs'] = pickle.load(pickle_fd)
            attack_traffic['internet_outputs'] = pickle.load(pickle_fd)

        return benign_traffic, attack_traffic


    def attack_features(self):
        """ Compute attack traffic feature characteristics """
        DeviceAttacks = Attacks(get_mac_addr(self.devices[0]))
        # all_annotations = get_all_attack_annotations()
        # for annotation in all_annotations:
        #     annotation.init_attack_flow_tuples()

        # DeviceAttacks.init_attack_flow_tuples() # Initialise required data_struct
        self.parse_attack_data(self.devices[1], DeviceAttacks)

        # if self.parse_attack_data(self.devices[0],DeviceAttacks):
            # print(self.local_inputs)
            # print(self.local_outputs)
            # print(self.internet_inputs)
            # print(self.internet_outputs)
            # self.pickle_feature_stats(self.devices[0]+"attack_traffic.pickle")
            # self.plot_feature_cdf()


    def sort_attack_traffic(self, attack_flows, DeviceAttacks, device_obj):
        """Put feature stats based on attack rate"""
        # Need to find attack rate of each flow from metadata. Find timestamp first then use timestamp as key to get metadata
        for flow in attack_flows:
            attack_rate = DeviceAttacks.get_attack_rate(attack_flows[flow])
            if flow in device_obj.internet_output_flows:
                self.aggregate_flow_feature_data(self.attack_traffic[attack_rate]['internet_outputs'], device_obj.flow_features[flow])
            if flow in device_obj.internet_input_flows:
                self.aggregate_flow_feature_data(self.attack_traffic[attack_rate]['internet_inputs'], device_obj.flow_features[flow])
            if flow in device_obj.local_input_flows:
                self.aggregate_flow_feature_data(self.attack_traffic[attack_rate]['local_inputs'], device_obj.flow_features[flow])
            if flow in device_obj.local_output_flows:
                self.aggregate_flow_feature_data(self.attack_traffic[attack_rate]['local_outputs'], device_obj.flow_features[flow])

    @staticmethod
    def set_coarse_grain_flows(sampling_rate, device_obj):
        device_obj.set_sampling_rate(sampling_rate)
        device_obj.set_device_activity()
        device_obj.set_location_direction_rates()
        # device_obj.plot_location_direction_rate(date)

    def save_attack_flows(self):
        """Higher order function for identifying and pickling attack flows -- also for test-driven dev"""
        # attack_annotations = get_all_attack_annotations()
        # d = ['Huebulb', 'iHome', 'Light Bulbs LiFX Smart Bulb']
        # # Load all traffic for each device
        # for attack_annotation in attack_annotations:
        #     attack_data = self.get_attack_data_path()
        #     if attack_annotation.device_name in d:
        #         continue
        #     device_objs = unpickle_network_trace_and_device_obj(str(attack_data), devices=attack_annotation.device_name).values()
        #     for device_obj in device_objs:
        #         for date in attack_annotation.relative_attack_timestamp:
        #             device_obj.identify_attack_flows(attack_annotation, date)
        pass

    def get_attack_data_path(self):
        return self.saved_traffic / "Attack"

    def parse_attack_data(self, device_addr, DeviceAttacks, coarse_grained_approach=True):
        """First identify attack flows => then parse through dataset and only extract features on attack flows"""
        attack_data_path = self.get_attack_data_path()
        def get_attack_flows(date):
            """Need to get attack flows corresponding to the correct date"""
            relevant_flows = []
            # print(DeviceAttacks.relative_attack_timestamp)
            date_attacks = DeviceAttacks.relative_attack_timestamp[date]
            # Need to ensure returned list values are in attack_flow_tuples
            for timestamp in date_attacks:
                if timestamp not in DeviceAttacks.attack_flow_tuples:
                    continue
                else:
                    # print("relevant flows", DeviceAttacks.attack_metadata[timestamp])
                    relevant_flows.append(DeviceAttacks.attack_flow_tuples[timestamp])

            return list(chain(*relevant_flows))

        def parse_data(annotation):
            flow_types = ['local_inputs', 'local_outputs', 'internet_inputs', 'internet_outputs']

            for date in annotation.relative_attack_timestamp:
                # test workflow for getting only one date
                attack_windows = get_attack_window_timestamps(device_name)
                if date != '18-06-01':
                    continue
                file_name = "_" + date
                device_name = annotation.device_name
                if device_name == "Belkin wemo motion sensor":
                    continue
                # print("DATE CHECK", file_name, date)
                attack_traffic = unpickle_network_trace_and_device_obj(str(attack_data_path), devices=device_name, files=file_name)
                for network_obj in attack_traffic:
                    for device_obj in attack_traffic[network_obj]:
                        device_obj.update_profile([], [], False)
                        device_obj.sort_flow_location(network_obj)
                        if coarse_grained_approach is False:
                            if DeviceAttacks.attack_flows_identified is False:
                                print(DeviceAttacks.attack_metadata)
                                print("preprocessing", device_obj.device_name)
                                device_obj.identify_attack_flows(annotation, date)
                            else:
                                print('extracting attack flow features')
                                attack_flows = DeviceAttacks.get_attack_flows(date)
                                # device_obj.plot_attack_flows(attack_flows)
                                # device_obj.get_flow_tuple_features((list(attack_flows.keys()), DeviceAttacks))
                                # self.sort_attack_traffic(attack_flows, DeviceAttacks, device_obj)
                                # self.sort_flow_stats(device_obj, attack_flows=attack_flows)
                        else:
                            self.set_coarse_grain_flows(100, device_obj)
                            # device_obj.plot_location_direction_rate(date)
                            # device_obj.plot_location_direction_pkt_rate(date)
                            for flow in flow_types:
                                data_struct = device_obj.get_rate_type_data_struct(flow)[1]
                                device_obj.plot_flow_for_attack_window(data_struct, flow, date)
                            # DeviceAttacks.identify_attack_flow_type(date)
                            # device_obj.find_attack_in_coarse_grained_flows(DeviceAttacks, date)
            print("FINISHED PARSING DATASET")

        def save_attack_flows():
            attack_annotations = get_all_attack_annotations()
            d = ['Huebulb', 'iHome', 'Light Bulbs LiFX Smart Bulb']
            # Load all traffic for each device
            for attack_annotation in attack_annotations:
                if attack_annotation.device_name == "Netatmo Welcom":
                    parse_data(annotation=attack_annotation)

                print('----{} ATTACK FLOW TABLE------'.format(attack_annotation.device_name))


        save_attack_flows()
        # parse_data()

        # if coarse_grained_approach:
        # else:
            # DeviceAttacks.is_attack_flows_identified()
            # if DeviceAttacks.attack_flows_identified is True:
            #     parse_data()
            #     # print('test done')
            # else:
            #     print(DeviceAttacks.attack_flow_tuples.items())
            #     print(len(DeviceAttacks.attack_flow_issue))
            # return True