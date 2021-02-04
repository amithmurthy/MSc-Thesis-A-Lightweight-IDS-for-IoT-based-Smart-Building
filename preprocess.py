from sklearn.decomposition import PCA
import matplotlib.pyplot as plt
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.pipeline import Pipeline
from sklearn.cluster import KMeans
import scipy.spatial.distance as sdist
from collections import OrderedDict
from scapy.all import *
from scapy.layers.l2 import Ether
import klepto as kl
from multiprocessing import Pool
from copy import deepcopy
# import tensorflow as tf
from pathlib import Path
import pandas as pd
import numpy as np
from tools import *
import time
from datetime import datetime
from io import FileIO
import pickle
""" Functions for normalising data """

class ModelDevice:
    # global first_headers
    # global second_headers
    # first_headers = ["250_local_inputs_mean", "250_local_inputs_std", "250_local_outputs_mean",
    #                  "250_local_outputs_std",
    #                  "250_internet_inputs_mean", "250_internet_inputs_std", "250_internet_outputs_mean",
    #                  "250_internet_outputs_std"]
    # second_headers = ["500_local_inputs_mean", "500_local_inputs_std", "500_local_outputs_mean",
    #                   "500_local_outputs_std",
    #                   "500_internet_inputs_mean", "500_internet_inputs_std", "500_internet_outputs_mean",
    #                   "500_internet_outputs_std"]

    def __init__(self, model_function, device_name, **kwargs):
        self.features = ['local_inputs_mean_bytes', 'local_inputs_std_bytes', 'local_outputs_mean_bytes', 'local_outputs_std_bytes',
                         'internet_inputs_mean_bytes', 'internet_inputs_std_bytes', 'internet_outputs_mean_bytes', 'internet_outputs_std_bytes',
                         'local_inputs_mean_pkts', 'local_inputs_std_pkts', 'local_outputs_mean_pkts', 'local_outputs_std_pkts', 'internet_inputs_mean_pkts',
                         'internet_inputs_std_pkts', 'internet_outputs_mean_pkts', 'internet_outputs_std_pkts', 'local_inputs_bytes_total', 'local_outputs_bytes_total',
                         'internet_inputs_bytes_total', 'internet_outputs_bytes_total', 'local_inputs_pkts_total', 'local_outputs_pkts_total', 'internet_inputs_pkts_total',
                         'internet_outputs_pkts_total']
        self.sampling_rates = kwargs['sampling_rate'] if 'sampling_rate' in kwargs else [5]
        self.first_time_scale_features = {sampling_rate: {feature: [] for feature in self.features} for sampling_rate in self.sampling_rates}
        self.second_time_scale_features = deepcopy(self.first_time_scale_features)
        self.device_folder = Path(r"C:\Users\amith\Documents\Uni\Masters\device_attributes") / device_name
        self.training_data = Path(r"C:\Users\amith\Documents\Uni\Masters\device_attributes") / device_name / "benign_"
        self.attack_data = Path(r"C:\Users\amith\Documents\Uni\Masters\device_attributes") / device_name / "attack_"
        self.save_plot_path = Path(r"C:\Users\amith\Documents\Uni\Masters\Graphs\Machine Learning") / device_name
        self.time_scales = kwargs['time_scales'] if 'time_scales' in kwargs else None
        self.experiment = kwargs['experiment'] if 'experiment' in kwargs else "all"
        self.feature_map = get_device_feature(device_name)
        print(device_name)
        self.device_name = device_name
        if model_function == 'preprocess':
            self.device_traffic = kwargs['device_traffic']
            self.data_type = kwargs['data_type'] if 'data_type' in kwargs else None
            self.saved_features = kwargs['saved_features'] if 'saved_features' in kwargs else False
            self.process_all_traffic()
        else:
            # k_clusters = 9
            # self.km_model = KMeans(n_clusters=k_clusters, init='random', n_init=10)
            self.model_function = model_function
            if model_function == 'train':
                self.train_type = kwargs['train_type'] if 'train_type' in kwargs else None
                self.create_clustering_model()
            elif model_function == 'anomaly_detection':
                self.time_scale_anomalies = None
                self.anomaly_timestamp = {}
                self.benign_model = {'internet':{}, 'local':{}}
                self.file_device_traffic_duration = {}
                self.relative_attack_timestamp = {}
                self.attack_metadata = {}
                self.anomaly_detection()
            elif model_function == 'validate':
                self.anomaly_timestamp = {}
                self.file_device_traffic_duration = {}
                self.relative_attack_timestamp = {}
                self.attack_metadata = OrderedDict
                self.validate_anomalies()

    def get_time_scale_features(self, device_obj):
        """TODO: Abstraction for time_scale required. Currently, only processes two time_scales at a time. """
        flows = ['local_inputs', 'local_outputs', 'internet_inputs', 'internet_outputs']
        first_time_scale = {}
        second_time_scale = {}

        def get_count_type_features(device, time_scale_dict, count_type):
            local_input_mean, local_input_std = device.get_mean_and_std(time_scale_dict['local_inputs'], count_type)
            local_output_mean, local_output_std = device.get_mean_and_std(time_scale_dict['local_outputs'],count_type)
            internet_input_mean, internet_input_std = device.get_mean_and_std(time_scale_dict['internet_inputs'],count_type)
            internet_output_mean, internet_output_std = device.get_mean_and_std(time_scale_dict['internet_outputs'],count_type)
            return [local_input_mean, local_input_std, local_output_mean, local_output_std, internet_input_mean, internet_input_std, internet_output_mean, internet_output_std]

        def get_total_count(device_obj, time_scale_dict, count_type):
            local_input = device_obj.get_total_byte_count(time_scale_dict['local_inputs'], count_type)
            local_output = device_obj.get_total_byte_count(time_scale_dict['local_outputs'], count_type)
            internet_input = device_obj.get_total_byte_count(time_scale_dict['internet_inputs'], count_type)
            internet_output = device_obj.get_total_byte_count(time_scale_dict['internet_outputs'], count_type)
            return [local_input, local_output, internet_input, internet_output]

        def get_features(time_scale_dict):
            # local_input_mean_bytes, local_input_std_bytes = device_obj.get_mean_and_std(time_scale_dict['local_inputs'], 'byte_count')
            # local_output_mean_bytes, local_output_std_bytes = device_obj.get_mean_and_std(time_scale_dict['local_outputs'], 'byte_count')
            # internet_input_mean_bytes, internet_input_std_bytes = device_obj.get_mean_and_std(time_scale_dict['internet_inputs'], 'byte_count')
            # internet_output_mean_bytes, internet_output_std_bytes = device_obj.get_mean_and_std(time_scale_dict['internet_outputs'], 'byte_count')
            # local_input_mean_pkts, local_input_std_pkts = device_obj.get_mean_and_std(time_scale_dict['local_inputs'], 'pkt_count')
            # local_output_mean_pkts, local_output_std_pkts = device_obj.get_mean_and_std(time_scale_dict['local_outputs'], 'pkt_count')
            # internet_input_mean_pkts, internet_input_std_pkts = device_obj.get_mean_and_std(time_scale_dict['internet_inputs'], 'pkt_count')
            # internet_output_mean_pkts, internet_output_std_pkts = device_obj.get_mean_and_std(time_scale_dict['internet_outputs'], 'pkt_count')
            if 'pkt_count' in self.feature_map:
                byte_features = get_count_type_features(device_obj, time_scale_dict, 'byte_count')
                pkt_features = get_count_type_features(device_obj, time_scale_dict, 'pkt_count')
                total_bytes = get_total_count(device_obj, time_scale_dict, 'byte_count')
                total_pkts = get_total_count(device_obj, time_scale_dict, 'pkt_count')
                return [byte_features, pkt_features, total_bytes, total_pkts]
            else:
                print('only byte_count extracted')
                byte_features = get_count_type_features(device_obj, time_scale_dict, 'byte_count')
                return byte_features
            # return local_input_mean, local_input_std, local_output_mean, local_output_std, internet_input_mean, internet_input_std, internet_output_mean, internet_output_std

        def set_features(extracted_feat_list, global_feature_dict):
            flat_list = [item for sublist in extracted_feat_list for item in sublist]
            for i in range(0, len(flat_list)):
                global_feature_dict[self.features[i]].extend(flat_list[i])

        # local time scale dict not initialised in for loops above as for loop necessary below i.e. less time complexity
        for sampling_rate in self.sampling_rates:
            first_time_scale[sampling_rate] = {attr: None for attr in flows}
            second_time_scale[sampling_rate] = {attr: None for attr in flows}
            device_obj.set_sampling_rate(sampling_rate)
            device_obj.set_location_direction_rates()
            for attribute in flows:
                first_time_scale[sampling_rate][attribute] = device_obj.create_traffic_volume_features(attribute, w_window=self.time_scales[0])
                second_time_scale[sampling_rate][attribute] = device_obj.create_traffic_volume_features(attribute, w_window=self.time_scales[1])
            first_time_scale_feat = get_features(first_time_scale[sampling_rate])
            second_time_scale_feat = get_features(second_time_scale[sampling_rate])
            set_features(first_time_scale_feat, self.first_time_scale_features[sampling_rate])
            set_features(second_time_scale_feat, self.second_time_scale_features[sampling_rate])

    def process_all_traffic(self):
        if self.saved_features is False:
            i = 1
            for device_obj in self.device_traffic:
                if i < 2:
                    self.get_time_scale_features(device_obj)
                else:
                    break
                i += 1
        print('finished feature extraction')
        self.save_device_traffic_attributes()
        # self.plot_graphs()

    def plot_graphs(self):
        print("plotting graphs")
        # self.plot_attribute_cluster("first", self.sampling_rates[0])
        # self.plot_attribute_cluster("second", self.sampling_rates[0])
        # self.compare_sampling_window(self.first_time_scale_features, 'internet', self.time_scales[0])
        # self.compare_sampling_window(self.first_time_scale_features, 'local', self.time_scales[0])
        # self.compare_sampling_window(self.second_time_scale_features, 'internet', self.time_scales[1])
        # self.compare_sampling_window(self.second_time_scale_features, 'local', self.time_scales[1])
        locations = ['local', 'internet']
        directions = ['inputs', 'outputs']
        for location in locations:
            self.plot_feature_correlation(self.first_time_scale_features, location, self.sampling_rates[0], directions[0], self.time_scales[0])
            self.plot_feature_correlation(self.first_time_scale_features, location, self.sampling_rates[0],
                                          directions[1], self.time_scales[0])
            self.plot_feature_correlation(self.first_time_scale_features, location, self.sampling_rates[1], directions[0], self.time_scales[0])
            self.plot_feature_correlation(self.first_time_scale_features, location, self.sampling_rates[1],
                                          directions[1], self.time_scales[0])
            self.plot_feature_correlation(self.second_time_scale_features, location, self.sampling_rates[0],
                                          directions[0], self.time_scales[1])
            self.plot_feature_correlation(self.second_time_scale_features, location, self.sampling_rates[0],
                                          directions[1], self.time_scales[1])
            self.plot_feature_correlation(self.second_time_scale_features, location, self.sampling_rates[1],
                                          directions[0], self.time_scales[1])
            self.plot_feature_correlation(self.second_time_scale_features, location, self.sampling_rates[1],
                                          directions[1], self.time_scales[1])

    def compare_sampling_window(self, time_scale, location, w_window):
        """time_scale = time_scale_features"""
        fig = plt.figure()
        ax = fig.add_subplot(1, 1, 1)
        name = "Sliding window " + str(w_window) +location + self.data_type + " singature"
        ax.set_title(name)
        ax.set_xlabel("mean (bytes)")
        ax.set_ylabel("standard deviation (bytes)")
        sample_rate_1 = time_scale[self.sampling_rates[0]]
        sample_rate_2 = time_scale[self.sampling_rates[1]]
        ax.scatter(sample_rate_1[location+'_inputs_mean_bytes'], sample_rate_1[location+'_inputs_std_bytes'], label= str(self.sampling_rates[0])+" "+location+' inputs', color='g', alpha=0.6)
        ax.scatter(sample_rate_2[location+'_inputs_mean_bytes'], sample_rate_2[location+'_inputs_std_bytes'], label= str(self.sampling_rates[1])+" "+location+' inputs', color='c', alpha=0.6)
        ax.scatter(sample_rate_1[location+'_outputs_mean_bytes'], sample_rate_1[location+'_outputs_std_bytes'], label= str(self.sampling_rates[0])+" "+location+' outputs', color='r', alpha=0.6)
        ax.scatter(sample_rate_2[location+'_outputs_mean_bytes'], sample_rate_2[location+'_outputs_std_bytes'], label= str(self.sampling_rates[1])+" "+location+' outputs', color='b', alpha=0.6)
        plt.legend(loc='best')
        plt.savefig(str(self.save_plot_path / self.device_name) + name + ".png")
        plt.show()

    def plot_feature_correlation(self, time_scale_features, location, sampling_rate, direction, time_scale):
        fig = plt.figure()
        ax = fig.add_subplot(1,1,1)
        name = str(time_scale) +" window" +" "+ str(sampling_rate) + " sampling rate"
        ax.set_title(name)
        ax.set_ylabel('Byte count (KB)')
        ax.set_xlabel('Packet count')
        save_path = self.save_plot_path / 'packet_size'
        location_direction = ['local_inputs', 'local_outputs', 'internet_inputs', 'internet_outputs']
        if save_path.is_dir() is False:
            save_path.mkdir()
            for x in location_direction:
                save_folder = save_path / x
                if save_folder.is_dir() is False:
                    save_folder.mkdir()

        def convert_to_KB(input_data):
            return [x / 1000 for x in input_data]

        ax.scatter(convert_to_KB(time_scale_features[sampling_rate][location+'_'+direction+'_mean_bytes']),
                   convert_to_KB(time_scale_features[sampling_rate][location+'_'+direction+'_std_bytes']))
        plt.savefig(str(self.save_plot_path/'packet_size'/ (location + '_'+ direction) / (name + '.png')))
        plt.show()

    def plot_attribute_cluster(self, time_scale_dict, sampling_rate):
        fig = plt.figure()
        ax = fig.add_subplot(1,1,1)
        if time_scale_dict == "first":
            time_scale = self.first_time_scale_features[sampling_rate]
            w_window = str(self.time_scales[0])
            name = self.device_name + " "+ w_window + " " + self.data_type
        elif time_scale_dict == "second":
            time_scale = self.second_time_scale_features[sampling_rate]
            w_window = str(self.time_scales[1])
            name = self.device_name +" "+ w_window + " " + self.data_type
        ax.set_title(name+" signature")
        ax.set_xlabel("mean (bytes)")
        ax.set_ylabel("standard deviation (bytes)")
        ax.scatter(time_scale['local_inputs_mean_bytes'], time_scale['local_inputs_std_bytes'], label="local inputs", color='r', alpha=0.6)
        ax.scatter(time_scale['local_outputs_mean_bytes'], time_scale['local_outputs_std_bytes'], label="local outputs", color='b', alpha=0.6)
        ax.scatter(time_scale['internet_inputs_mean_bytes'], time_scale['internet_inputs_std_bytes'], label='internet inputs', color='g', alpha=0.6)
        ax.scatter(time_scale['internet_outputs_mean_bytes'], time_scale['internet_outputs_std_bytes'], label='internet outputs', color='c', alpha=0.6)
        plt.legend(loc='best')
        plt.savefig(str(self.save_plot_path / self.device_name) + name + str(sampling_rate) +"attributes.png")
        plt.show()

    def normalise_time_scale(self, df, ts):
        file_path = Path(r"C:\Users\amith\Documents\Uni\Masters\device_attributes") / self.device_name / "kmeans-model"/ (str(ts) +'scaler.pkl')
        headers = list(df.columns)
        if self.data_type == 'benign':
            scaler = StandardScaler()
            df[headers] = scaler.fit_transform(df.values)
            pickle.dump(scaler, open(str(file_path), 'wb'))
            print('scaler mean', scaler.mean_)
            print('scaler std', scaler.var_)
        elif self.data_type == 'attack':
            print('saved scaler used')
            scaler = pickle.load(open(str(file_path), 'rb'))
            df[headers] = scaler.transform(df.values)
        return df

    @staticmethod
    def get_time_scale_df(time_scale_features, time_scale):
        df = pd.DataFrame()
        for sampling_rate in time_scale_features:
            for feature in time_scale_features[sampling_rate]:
                header = str(sampling_rate) + '_' + str(time_scale) + '_' + str(feature)
                df[header] = pd.Series(time_scale_features[sampling_rate][feature])
        return df

    def save_device_traffic_attributes(self):
        """Takes in one single device instance"""
        # rows = zip(first_time_scale_cols, second_time_scale_cols)
        file_path = Path(r"C:\Users\amith\Documents\Uni\Masters\device_attributes") / self.device_name / "normalised"
        save_feature_df = self.device_folder / 'features'
        if self.saved_features is False:
            df_first_time_scale, df_second_time_scale = self.get_time_scale_df(self.first_time_scale_features, self.time_scales[0]), self.get_time_scale_df(self.second_time_scale_features, self.time_scales[1])
        else:
            df_first_time_scale, df_second_time_scale = pd.read_csv(str(save_feature_df / str(self.time_scales[0] + self.data_type + "s.csv"))), pd.read_csv(str(save_feature_df / str(self.time_scales[1] + self.data_type + "s.csv")))
        # for key in self.first_time_scale_features:
        #     # df[first_headers[i]] = pd.Series(first_time_scale_cols[i])
        #     header = str(self.time_scales[0]) + '_' + str(key)
        #     df_first_time_scale[header] = pd.Series(self.first_time_scale_features[key])
        #     # print(first_headers[i], len(first_time_scale_cols[i]))
        # for key in self.second_time_scale_features:
        #     # df[second_headers[i]] = pd.Series(second_time_scale_cols[i])
        #     header = str(self.time_scales[1]) + '_' + str(key)
        #     df_second_time_scale[header] = pd.Series(self.second_time_scale_features[key])
        #     # print(second_headers[i], len(second_time_scale_cols[i]))


        # df_first_time_scale.to_csv(str(file_path) + "second.csv")
        # Compute z-scores for attributes
        z_score_cols = []
        def z_score(cols, df, org_df, ts):
            print('calculating z-score')
            file_path = Path(r"C:\Users\amith\Documents\Uni\Masters\device_attributes") / self.device_name / "kmeans-model" / (str(ts) + '-zscore')
            if file_path.is_dir() is False:
                file_path.mkdir()
            for col in cols:
                col_zscore = col + '_zscore'
                z_score_cols.append(col_zscore)
                if self.data_type == 'benign':
                    mean = org_df[col].mean()
                    std = org_df[col].std()
                    print('my way',col,'std:', std)
                    print('my way',col,'mean',mean)
                    # print('ddof=0', org_df[col].std(ddof=0))
                    df[col_zscore] = (org_df[col] - mean) / std
                    pickle.dump(mean, open(str(file_path / (col+'_mean.pickle')), 'wb'))
                    pickle.dump(std, open(str(file_path / (col+'_std.pickle')), 'wb'))
                elif self.data_type == 'attack':
                    mean = pickle.load(open(str(file_path / (col+'_mean.pickle')), 'rb'))
                    std = pickle.load(open(str(file_path / (col+'_std.pickle')), 'rb'))
                    df[col_zscore] = (org_df[col] - mean) / std
            return df

        def segragate_location(df):
            columns = df.columns
            local_traffic = pd.DataFrame()
            internet_traffic = pd.DataFrame()
            for col in columns:
                if 'local' in col:
                    local_traffic[col] = df[col].values
                    assert local_traffic[col].equals(df[col])
                elif 'internet' in col:
                    internet_traffic[col] = df[col].values
                    assert internet_traffic[col].equals(df[col])
            return local_traffic, internet_traffic

        def save_segragation(df,time_scale,location):
            df.to_csv(str(file_path/ str(time_scale + self.data_type + location+".csv")))

        print('saving')
        df_first_time_scale = df_first_time_scale.fillna(0)
        df_second_time_scale = df_second_time_scale.fillna(0)
        df_first_time_scale.to_csv(str(save_feature_df / (str(self.time_scales[0]) + self.data_type + "s.csv")))
        df_second_time_scale.to_csv(str(save_feature_df / (str(self.time_scales[1]) + self.data_type + "s.csv")))

        # df_first_time_scale.to_csv(str(file_path / str(self.time_scales[0]))+self.data_type+".csv")
        # df_second_time_scale = self.normalise_time_scale(df_second_time_scale, self.time_scales[1])
        # df_second_time_scale.to_csv(str(file_path / str(self.time_scales[1]))+self.data_type+".csv")
        df_first_time_zscore = z_score(list(df_first_time_scale.columns), pd.DataFrame(), df_first_time_scale, self.time_scales[0])
        df_second_time_zscore = z_score(list(df_second_time_scale.columns), pd.DataFrame(), df_second_time_scale, self.time_scales[1])
        # std_scaler_test = self.normalise_time_scale(df_first_time_scale, self.time_scales[0])
        # df_first_time_zscore.to_csv(str(file_path / str(self.time_scales[0]))+self.data_type+".csv")
        # df_second_time_zscore.to_csv(str(file_path / str(self.time_scales[1]))+self.data_type+".csv")
        local_features_1, internet_features_1 = segragate_location(df_first_time_zscore)
        local_features_2, internet_features_2 = segragate_location(df_second_time_zscore)
        save_segragation(local_features_1, str(self.time_scales[0]), 'local')
        save_segragation(internet_features_1, str(self.time_scales[0]), 'internet')
        save_segragation(local_features_2, str(self.time_scales[1]), 'local')
        save_segragation(internet_features_2, str(self.time_scales[1]), 'internet')
        # std_scaler_test.to_csv(str(self.device_folder/ "standard-scaler-test.csv"))
        # test = self.clean_dataset(df_second_time_zscore)
        # df_first_time_scale = clean_dataset(df_first_time_scale)


    def create_clustering_model(self):
        """TODO: Assign the timescale dataset to a variable i.e. which timescale dataset is being trained"""
        location_models = self.get_location_models()
        # p = Pool(len(location_models.items()))
        # print('time_scale_files', time_scale_files)
        # p.map(self.train_time_scale_model, time_scale_files)
        if self.experiment != 'all':
            self.train_time_scale_model(self.experiment)
        else:
            for location in location_models:
                for file in location_models[location]:
                    if file == '50s.csv' or file == '100s.csv':
                        continue
                    self.train_time_scale_model(location,file)

    def train_time_scale_model(self, location, file):
        """Gets csv and creates clustering model for time_scale features"""
        print('training on', location, file)
        dataset = Path(str(self.training_data)+location) / file
        df = pd.read_csv(str(dataset), index_col=0)
        if self.train_type == 'find_k':
            file_name = location + file
            self.find_k(df, file_name)
        else:
            self.save_model(df, file, location)

    def get_location_models(self):
        location_model = {'internet':[], 'local':[]}
        for location in location_model:
            training_data = Path(str(self.training_data)+location)
            for file in training_data.iterdir():
                location_model[location].append(file.name)
        return location_model

    def train_model(self, df, k_clusters):
        """ Clustering model instantiated
        df: csv in pd.DataFrame format
        inspection: optional argument to return cluster model for anomaly detection
        """
        km_model = KMeans(n_clusters=k_clusters, init='random', n_init=10)
        data = df.values
        if self.model_function == 'anomaly_detection':
            model = self.km_model.fit(data)
            return model
        else:
            clusters = km_model.fit_predict(data)
            centroids = km_model.cluster_centers_
            # df['cluster'] = self.km_model.labels_
            # dist = sdist.cdist(data, centroids)
            # print(dist)
            # self.km_model = self.km_model.fit(data)
            print("Shape of data", centroids.shape)
            # dimensionality = centroids.shape[1]
            cluster_boundary, cluster_distances = self.find_cluster_boundary(data, centroids, clusters)
            return km_model, cluster_boundary, cluster_distances

    def save_model(self, df, file, location):
        time_scale = str(file)[:-4]
        clusters = get_device_cluster(self.device_name, location, time_scale)
        km_model, cluster_boundary, cluster_distances = self.train_model(df,clusters)
        folder_name = self.device_folder / "kmeans-model" / location
        if folder_name.is_dir() is False:
            folder_name.mkdir()
        file_name = folder_name / time_scale
        ar = kl.archives.dir_archive(name=file_name, serialized=True, cached=True, protocol=4)
        ar['cluster_model'] = km_model
        ar['cluster_boundary'] = cluster_boundary
        ar['cluster_distances'] = cluster_distances
        ar.dump()
        ar.clear()

    def save_anomalies(self):
        file_name = self.device_folder / "kmeans-model"
        ar = kl.archives.dir_archive(name=file_name, serialized=True, cached=True, protocol=4)
        ar['anomalies'] = self.time_scale_anomalies
        ar.dump()
        ar.clear()

    def get_instance_distance_points(self, data, cx, cy, cz, i_centroid, cluster_labels):
        euclidean_distances = [np.sqrt((x - cx) ** 2 + (y - cy) ** 2 + (z - cz) ** 2) for (x, y, z) in
                               data[cluster_labels == i_centroid]]
        # print('centroid distances',euclidean_distances)
        return euclidean_distances

    def find_cluster_boundary(self, data, centroids, cluster_labels):
        cluster_distances = {i: [] for i in range(len(centroids))}
        test = {}
        # for i, (cx, cy, cz) in enumerate(centroids):
        #     if i not in test:
        #         test[i] = self.get_instance_distance_points(data, cx, cy, cz, i, cluster_labels)
            # centroid_distances[i].extend(distance)

        # for i_centroid in enumerate(centroids):
        #     cluster_distances[i_centroid] = sdist.cdist(data[cluster_labels == i_centroid], i_centroid)
        df = pd.DataFrame({'cluster': cluster_labels})

        dists = pd.DataFrame(
            sdist.cdist(data, centroids),
            columns=['dist_{}'.format(i) for i in range(len(centroids))],
            index=df.index)
        df = pd.concat([df, dists], axis=1)

        save_distance_path = self.device_folder / "distance_dataframe.csv"
        df.to_csv(str(save_distance_path))
        len_of_df = list(df.index.values)[-1]
        """Should be iloc? iloc gets index location"""
        for i in range(0, len_of_df+1):
            cluster = df.loc[i].cluster
            dist = 'dist_' + str(int(cluster))
            cluster_distances[cluster].append(df.loc[i][dist])

        if self.model_function == 'anomaly_detection':
            return cluster_distances
        else:
            cluster_boundary = {centroid: np.percentile(np.array(cluster_distances[centroid]), 97.5) for centroid in
                                cluster_distances}
            print(cluster_boundary)
            return cluster_boundary, cluster_distances

    def anomaly_detection(self):
        self.get_benign_model()
        self.time_scale_anomalies = {location: {time_scale: {'anomalies':[], 'anomaly_index':[]} for time_scale in self.benign_model[location]} for location in self.benign_model}
        # p = Pool(len(self.benign_model.keys()))
        # p.map(self.inspect_traffic, self.benign_model.keys())
        for location in self.benign_model:
            for time_scale in self.benign_model[location]:
                self.inspect_traffic(time_scale, location)
        self.save_anomalies()
        self.validate_anomalies()

        # print(self.time_scale_anomalies['250s'])
        # print(self.time_scale_anomalies['500s'])

    def inspect_traffic(self, time_scale, location):
        """Cluster boundary for time_scale model are the arguments"""
        print("inspecting", location, time_scale)
        benign_data = self.device_folder / ("benign_"+location) / (str(time_scale) + '.csv')
        attack_file = self.device_folder / ("attack_"+location) / (str(time_scale) + '.csv')

        benign_df = pd.read_csv(str(benign_data))
        # test = KMeans(n_clusters=5)
        # test_x = test.fit(benign_df.values)
        inspect_df = pd.read_csv(str(attack_file), index_col=0)
        inspect_data = inspect_df.values
        # attack_centroids = test.fit_predict(inspect_data)
        # print("attack", test.cluster_centers_.shape)
        benign_cluster_model = self.benign_model[location][time_scale]['cluster_model']
        # self.validate_model(benign_cluster_model, time_scale)
        print(attack_file)
        # X_test = benign_cluster_model.transform(inspect_data)

        results = benign_cluster_model.predict(inspect_data)
        print("predicted attack data")
        # cluster_points_distances = self.find_cluster_boundary(inspect_data, benign_cluster_model.cluster_centers_, results)
        cluster_points_distances = self.find_cluster_boundary(inspect_data, self.benign_model[location][time_scale]['benign_centroids'], results)
        cluster_map = pd.DataFrame()
        cluster_map['data_index'] = inspect_df.index.values
        cluster_map['cluster'] = results
        cluster_map.to_csv(str(self.device_folder/time_scale)+"index_data_clusters.csv")
        cluster_boundary = self.benign_model[location][time_scale]['cluster_boundary']
        self.find_anomalies(location, time_scale, cluster_boundary, cluster_points_distances, cluster_map)

    def find_anomalies(self, location, time_scale, cluster_boundary, cluster_distances, cluster_map):
        # print(time_scale, 'boundaries', cluster_boundary)
        for centroid in cluster_distances:
            # print(time_scale, 'distances',  cluster_distances[centroid])
            centroid_data_index = list(cluster_map[cluster_map.cluster == centroid].data_index.values)
            i = 0
            if time_scale == '150s' or time_scale == '200s':
                print(time_scale," boundary outlier detection")
            for instance in cluster_distances[centroid]:
                if instance > cluster_boundary[centroid]:
                    self.time_scale_anomalies[location][time_scale]['anomalies'].append(instance)
                    self.time_scale_anomalies[location][time_scale]['anomaly_index'].append(centroid_data_index[i])
                elif instance == cluster_boundary[centroid]:
                    print('equal to boundary')
                i += 1


    def validate_anomalies(self):
        """TODO: Need to save anomaly outputs and extract for each experiment before running validation - requires methods"""
        self.correlate_index_timestamp()
        # extract attack annotations timestamp
        self.attack_annotations()
        self.reconstruct_device_activity()
        # if self.validate_device_activity() is True:
        self.convert_annotations_to_timescale_index()
            # self.link_annotations_and_output()

    def validate_device_activity(self):
        # Validate total device duration in dataset
        csv_file_duration = self.get_total_device_time('300s')
        last_file = list(self.relative_attack_timestamp.keys())[-1]
        pcap_duration = 0
        for i in self.file_device_traffic_duration:
            pcap_duration += self.file_device_traffic_duration[i]
        if csv_file_duration - pcap_duration < 1000:
            print("device time stamp matches")
        return True

    def convert_annotations_to_timescale_index(self):
        print("convert annotations to time scale index")

        time_scale_anomaly_index = {location: {time_scale: [] for time_scale in self.time_scale_anomalies[location]} for location in self.time_scale_anomalies}
        global_attack_timestamp = []

        def increment_device_time(file):
            files = list(self.file_device_traffic_duration.keys())
            file_index = files.index(file)
            if file_index == 0:
                return 0
            else:
                total_device_time = 0
                for i in range(0, file_index):
                    total_device_time += self.file_device_traffic_duration[files[i]]
                return total_device_time

        for file in self.relative_attack_timestamp:
            device_duration = increment_device_time(file)
            # print('device_duration', device_duration)
            # print('relative times', self.relative_attack_timestamp[file])
            for rel_attack_time in self.relative_attack_timestamp[file]:
                start = int(device_duration + rel_attack_time[0])
                end = int(device_duration + rel_attack_time[1])
                print((start, end))
                global_attack_timestamp.append((start, end))


        def ts_index_range(attack_timestamp, time_scale):
            time_scale = int(time_scale[:-1])
            start_i, end_i = int((attack_timestamp[0] / time_scale) - 1), int((attack_timestamp[1] / time_scale) - 1)
            return [i for i in range(start_i, end_i + 1, 1)]

        for attack_time in global_attack_timestamp:
            for location in time_scale_anomaly_index:
                for time_scale in time_scale_anomaly_index[location]:
                    time_scale_anomaly_index[location][time_scale].extend(ts_index_range(attack_time, time_scale))

        # for ts in time_scale_anomaly_index:
        #     t = int(ts[:-1])
        # rel_time = [500 * i for i in time_scale_anomaly_index['500s']]

        tp = 0
        total = 0
        # print(global_attack_timestamp)
        # print(len(rel_time))
        int_anomalies = []
        # for time in self.anomaly_timestamp['300s']:
        #     int_anomalies.append(int(time))

        # print('300s anomalies', int_anomalies)
        tp_anomalies = {location:{ts:[] for ts in self.time_scale_anomalies[location]} for location in self.time_scale_anomalies}
        meta_data_keys = list(self.attack_metadata.keys())
        for location in self.time_scale_anomalies:
            for ts in self.anomaly_timestamp[location]:
                print(ts, len(self.anomaly_timestamp[location][ts]))
                for anomaly in self.anomaly_timestamp[location][ts]:
                    i = 0
                    for attack_ts in global_attack_timestamp:
                        if attack_ts[0] <= anomaly <= attack_ts[1]:
                            tp += 1
                            tp_anomalies[location][ts].append((int(anomaly), self.attack_metadata[meta_data_keys[i]]['attack_type']))
                        i += 1
        for location in tp_anomalies:
            print(location)
            # print(tp_anomalies[ts])
            for ts in tp_anomalies[location]:
                if ts == '50s' or ts == '100s':
                    continue
                total = len(self.anomaly_timestamp[location][ts])
                tp = len(tp_anomalies[location]['50s'])
                print('len of identified', tp)
                print('TP:',  tp / total)
                print('FP:', (total - tp) / total)
                print(tp_anomalies['internet'][ts])
        # print()


    def link_annotations_and_output(self):
        pass


    def reconstruct_device_activity(self):
        processed_attack_traffic = r"C:\Users\amith\Documents\Uni\Masters\processed-traffic\Attack"
        network_instances = unpickle_network_trace_and_device_obj(processed_attack_traffic, devices=self.device_name)
        # file_device_traffic_duration = {network_obj.file_name: None for network_obj in network_instances}
        for network_obj in network_instances:
            for device_obj in network_instances[network_obj]:
                assert len(network_instances[network_obj]) < 2
                device_obj.update_profile([], [], compute_attributes=False)
                self.file_device_traffic_duration[network_obj.file_name[:-5]] = device_obj.set_device_activity('duration')

    def attack_annotations(self):
        """TODO: Need to refactor the process of adding to attacks dict"""
        device_mac_addr = get_mac_addr(self.device_name).replace(':', '')
        # print('device mac addr', device_mac_addr)
        annotation_path = Path(r"C:\Users\amith\Documents\Uni\Masters\Datasets\UNSW\2018\annotations\annotations") / (device_mac_addr + ".csv")
        col_names = ['start_time', 'end_time', 'attack_features', 'attack_type']
        annotations = pd.read_csv(str(annotation_path), names=col_names)
        attacks = {} #attack time for each date {'2018-06-01':[(start, end)...],...}
        def nest_metadata(key, timestamp, start_epoch):
            if key in attacks:
                attacks[key][timestamp] = {'attack_features': annotations.loc[annotations['start_time'] == start_epoch, 'attack_features'].iloc[0], 'attack_type': annotations.loc[annotations['start_time'] == start_epoch,'attack_type'].iloc[0]}
            else:
                attacks[key] = {}
                attacks[key][timestamp] = {'attack_features': annotations.loc[annotations['start_time'] == start_epoch, 'attack_features'].iloc[0], 'attack_type': annotations.loc[annotations['start_time'] == start_epoch,'attack_type'].iloc[0]}

        for start_epoch, end_epoch in zip(annotations['start_time'], annotations['end_time']):
            # start_date = time.strftime('%Y-%m-%d', time.localtime(i))
            start_date = datetime.utcfromtimestamp(start_epoch).strftime('%Y-%m-%d')
            end_date = datetime.utcfromtimestamp(end_epoch).strftime('%Y-%m-%d') #(time.strftime('%Y-%m-%d', time.localtime(j))[2:])
            start_date, end_date = start_date[2:], end_date[2:]
            if start_date == end_date:
                nest_metadata(start_date, (datetime.utcfromtimestamp(start_epoch).strftime('%H:%M:%S'), datetime.utcfromtimestamp(end_epoch).strftime('%H:%M:%S')), start_epoch)
            else:
                print('different dates', start_epoch)
                nest_metadata(start_date, (datetime.utcfromtimestamp(start_epoch).strftime('%H:%M:%S'), "23:59:59"), start_epoch)
                nest_metadata(end_date, ("00:00:00", datetime.utcfromtimestamp(end_epoch).strftime('%H:%M:%S')), start_epoch)

        device_first_pkt = self.get_attack_file_first_pkt_epoch(attacks)
        self.get_relative_attack_timestamps(device_first_pkt, attacks)
        #Link relative time to metadata
        for date in self.relative_attack_timestamp:
            relative_timestamps = self.relative_attack_timestamp[date]
            date_timestamps = attacks[date].keys()
            for rel_time, date_time in zip(relative_timestamps, date_timestamps):
                self.attack_metadata[rel_time] = attacks[date][date_time]

    def get_relative_attack_timestamps(self, device_first_pkt, attack_times):

        def attack_duration(attack_datetime):
            fmt = '%H:%M:%S'
            return (datetime.strptime(attack_datetime[1], fmt) - datetime.strptime(attack_datetime[0],
                                                                                   fmt)).total_seconds()
        for file in device_first_pkt:
            # print('first pkt time in file', device_first_pkt[file])
            # print('attack timestamps in file', attack_times[file])
            self.relative_attack_timestamp[file] = []
            first_pkt_time = datetime.strptime(device_first_pkt[file], '%H:%M:%S')
            attack_timestamps = list(attack_times[file].keys())
            for attack_timestamp in attack_timestamps:
                rel_attack_start = ((datetime.strptime(attack_timestamp[0], '%H:%M:%S')) - first_pkt_time).total_seconds()
                rel_attack_duration = attack_duration(attack_timestamp)
                rel_attack_end = rel_attack_start + rel_attack_duration
                self.relative_attack_timestamp[file].append((rel_attack_start, rel_attack_end))
                if rel_attack_start < 0:
                    print('negative time', rel_attack_start, rel_attack_end)


                # print('rel_diff', rel_dif, 'file', file)
                # rel_attack_end = (datetime.strptime(attack_timestamp[1], '%H:%M:%S') - first_pkt_time).total_seconds()
        # print(self.relative_attack_timestamp)

    def get_attack_file_first_pkt_epoch(self, attack_times):
        attack_dataset = Path(r"C:\Users\amith\Documents\Uni\Masters\Datasets\UNSW\2018\Attack Data")
        first_pkt_time = {attack_file: None for attack_file in list(attack_times.keys())}
        for pcap in attack_dataset.iterdir():
            if pcap.name[:-5] in list(attack_times.keys()):
                first_pkt_epoch = self.read_pcap(FileIO(pcap))
                # print(first_pkt_epoch)
                first_pkt_time[pcap.name[:-5]] = datetime.utcfromtimestamp(first_pkt_epoch).strftime('%H:%M:%S')
                try:
                    pkt_date = datetime.utcfromtimestamp(first_pkt_epoch).strftime("%Y-%m-%d")
                    # print(pkt_date, "20" + pcap.name[:-5])
                    assert pkt_date == ("20" + pcap.name[:-5])
                except AssertionError:
                    print("First pkt date is different to file")
                    print("pkt date", pkt_date)
                    print("file", pcap.name)
                # print('test', datetime.utcfromtimestamp(first_pkt_epoch).strftime('%H:%M:%S'))
        return first_pkt_time

    def read_pcap(self, pcap_file):
        device_filter = get_mac_addr(self.device_name)
        count = 0
        print('reading',pcap_file)
        for pkt_data, pkt_metadata in RawPcapReader(pcap_file):
            count += 1
            ether_pkt = Ether(pkt_data)
            if ether_pkt.src == device_filter or ether_pkt.dst == device_filter:
                # print('pkt ordinal', count)
                return ((pkt_metadata.tshigh << 32) | pkt_metadata.tslow) / pkt_metadata.tsresol
            else:
                continue

    def correlate_index_timestamp(self):
        for location in self.time_scale_anomalies:
            for time_scale in self.time_scale_anomalies[location]:
                # total_device_time = self.get_total_device_time(time_scale)
                # print(time_scale, 'total duration', total_device_time)
                # Data structure to store anomaly timestamp (anomaly_timestamp) is intiated
                self.anomaly_timestamp[location] = {ts:[] for ts in self.time_scale_anomalies[location]}
                for centroid in self.time_scale_anomalies[location][time_scale]:
                    for anomaly_index in self.time_scale_anomalies[location][time_scale][centroid]:
                        anomaly_timestamp = (anomaly_index + 1) * int(time_scale[:-1])
                        self.anomaly_timestamp[location][time_scale].append(anomaly_timestamp)
                        # self.anomaly_timestamp[time_scale].append(anomaly_index)
            # print(time_scale, 'anomaly timestamp', self.anomaly_timestamp[time_scale])


    def get_total_device_time(self, time_scale):
        file_in = self.device_folder / (str(time_scale) + "index_data_clusters.csv")
        cluster_map = pd.read_csv(str(file_in))
        last_index = list(cluster_map.data_index.values)[-1]
        return (last_index + 1) * int(time_scale[:-1])

    def get_benign_model(self):
        saved_model = self.device_folder / "kmeans-model"
        time_scale_boundary = {}
        # time_scale_boundary = {time_scale.name: None for time_scale in saved_model.iterdir()}
        # self.benign_distances = {time_scale.name: None for time_scale in saved_model.iterdir()}
        for model in saved_model.iterdir():
            # Folder names greater than len 4 are not km model
            if 'internet' not in model.name and 'local' not in model.name:
                continue
            print(model.name)
            location = 'internet' if 'internet' in model.name else 'local'
            for time_scale_model in model.iterdir():
                db = saved_model / location / time_scale_model.name
                d = kl.archives.dir_archive(name=db, serialized=True)
                d.load('cluster_boundary')
                d.load('cluster_distances')
                d.load('cluster_model')
                # time_scale_boundary[time_scale.name] = d['cluster_boundary']
                # model_features = ['cluster_model', 'cluster_distances', 'cluster_boundary']
                self.benign_model[location][time_scale_model.name] = {}
                self.benign_model[location][time_scale_model.name]['cluster_model'] = d['cluster_model']
                self.benign_model[location][time_scale_model.name]['benign_distances'] = d['cluster_distances']
                self.benign_model[location][time_scale_model.name]['benign_centroids'] = d['cluster_model'].cluster_centers_
                self.benign_model[location][time_scale_model.name]['cluster_boundary'] = d['cluster_boundary']
        # print(time_scale_boundary)
        # print('time_scale_boundary', time_scale_boundary)
        # return time_scale_boundary

    def plot_pca_components(self, df, time_scale):
        fig = plt.figure()
        ax = fig.add_subplot(1, 1, 1)
        ax.scatter(df['0'], df['1'])
        ax.set_xlabel("Principal Component 1")
        ax.set_ylabel("Principal Component 2")
        ax.set_title("Reduced dimension")
        plt.savefig(time_scale + "PCA.png")
        plt.show()

    def find_k(self, df, file):
        print('finding K', file)
        x = df.values
        K = range(2,20)
        inertia = []
        for k in K:
            km = KMeans(n_clusters=k, init="random",n_init=10)
            km = km.fit(x)
            inertia.append(km.inertia_)
        plt.plot(K, inertia, 'bx-')
        plt.xlabel('k')
        plt.ylabel('Inertia')
        plt.title(file+'Elbow method')
        plt.savefig(str(self.save_plot_path / file)+'elbowmethod.png')
        print("elbow method printed in machine learning plot folder")
        plt.show()
        # print(inertia)

    def clean_dataset(self, df):
        df.dropna(inplace=True)
        indices_to_keep = ~df.isin([np.nan, np.inf, -np.inf]).any(1)
        return df[indices_to_keep].astype(np.float64)

