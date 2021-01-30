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
# import tensorflow as tf
from pathlib import Path
import pandas as pd
import numpy as np
from tools import get_mac_addr, unpickle_network_trace_and_device_obj, get_device_cluster
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
        self.features = ['local_inputs_mean', 'local_inputs_std', 'local_outputs_mean', 'local_outputs_std',
                         'internet_inputs_mean', 'internet_inputs_std', 'internet_outputs_mean', 'internet_outputs_std']
        self.first_time_scale_features = {feature: [] for feature in self.features}
        self.second_time_scale_features = {feature: [] for feature in self.features}
        self.device_folder = Path(r"C:\Users\amith\Documents\Uni\Masters\device_attributes") / device_name
        self.training_data = Path(r"C:\Users\amith\Documents\Uni\Masters\device_attributes") / device_name / "Benign"
        self.attack_data = Path(r"C:\Users\amith\Documents\Uni\Masters\device_attributes") / device_name / "Attack"
        self.save_plot_path = Path(r"C:\Users\amith\Documents\Uni\Masters\Graphs\Machine Learning") / device_name
        self.time_scales = kwargs['time_scales'] if 'time_scales' in kwargs else None
        self.experiment = kwargs['experiment'] if 'experiment' in kwargs else "all"
        print(device_name)
        self.device_name = device_name
        if model_function == 'preprocess':
            self.device_traffic = kwargs['device_traffic']
            self.data_type = kwargs['data_type'] if 'data_type' in kwargs else None
            self.process_all_traffic()
        else:
            k_clusters = get_device_cluster(device_name)
            self.km_model = KMeans(n_clusters=k_clusters, init='random', n_init=10)
            self.model_function = model_function
            if model_function == 'train':
                self.train_type = kwargs['train_type'] if 'train_type' in kwargs else None
                self.create_clustering_model()
            elif model_function == 'anomaly_detection':
                self.time_scale_anomalies = None
                self.anomaly_timestamp = {}
                self.benign_model = {}
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


    def get_time_scale_features(self, device_obj, data_type):
        """TODO: Abstraction for time_scale required. Currently, only processes two time_scales at a time. """
        flows = ['local_inputs', 'local_outputs', 'internet_inputs', 'internet_outputs']
        first_time_scale = {attr: None for attr in flows}
        second_time_scale = {attr: None for attr in flows}
        print("Getting time scale features...")
        for attribute in flows:
            first_time_scale[attribute] = device_obj.create_traffic_volume_features(attribute, w_window=self.time_scales[0])
            second_time_scale[attribute] = device_obj.create_traffic_volume_features(attribute, w_window=self.time_scales[1])

        def get_features(time_scale_dict, time_scale_feature):
            local_input_mean, local_input_std = device_obj.get_mean_and_std(time_scale_dict['local_inputs'])
            local_output_mean, local_output_std = device_obj.get_mean_and_std(time_scale_dict['local_outputs'])
            internet_input_mean, internet_input_std = device_obj.get_mean_and_std(time_scale_dict['internet_inputs'])
            internet_output_mean, internet_output_std = device_obj.get_mean_and_std(time_scale_dict['internet_outputs'])
            return local_input_mean, local_input_std, local_output_mean, local_output_std, internet_input_mean, internet_input_std, internet_output_mean, internet_output_std

        def set_features(time_scale_feat,time_scale_feat_dict):
            for i in range(0, len(self.features)):
                time_scale_feat_dict[self.features[i]].extend(time_scale_feat[i])

        first_time_scale_feat = get_features(first_time_scale, self.first_time_scale_features)
        second_time_scale_feat = get_features(second_time_scale, self.second_time_scale_features)
        set_features(first_time_scale_feat, self.first_time_scale_features)
        set_features(second_time_scale_feat, self.second_time_scale_features)


    def process_all_traffic(self):
        for device_obj in self.device_traffic:
            self.get_time_scale_features(device_obj, 'benign')
        self.save_device_traffic_attributes()
        # self.plot_attribute_cluster("first")
        # self.plot_attribute_cluster("second")

    def plot_attribute_cluster(self, time_scale_dict):
        fig = plt.figure()
        ax = fig.add_subplot(1,1,1)
        if time_scale_dict == "first":
            time_scale = self.first_time_scale_features
            name = self.device_name + " "+str(self.time_scales[0]) + " " + self.data_type
        elif time_scale_dict == "second":
            time_scale = self.second_time_scale_features
            name = self.device_name +" "+ str(self.time_scales[1]) + " " + self.data_type

        ax.set_title(name+" signature")
        ax.set_xlabel("mean (bytes)")
        ax.set_ylabel("standard deviation (bytes)")
        ax.scatter(time_scale['local_inputs_mean'], time_scale['local_inputs_std'], label="local inputs", color='r', alpha=0.6)
        ax.scatter(time_scale['local_outputs_mean'],
                   time_scale['local_outputs_std'], label="local outputs", color='b', alpha=0.6)
        ax.scatter(time_scale['internet_inputs_mean'], time_scale['internet_inputs_std'], label='internet inputs', color='g', alpha=0.6)
        ax.scatter(time_scale['internet_outputs_mean'],
                   time_scale['internet_outputs_std'], label='internet outputs', color='c', alpha=0.6)
        plt.legend(loc='best')
        plt.savefig(str(self.save_plot_path) + name + "attributes.png")
        plt.show()

    def normalise_time_scale(self, df, ts):
        file_path = Path(r"C:\Users\amith\Documents\Uni\Masters\device_attributes") / self.device_name / "kmeans-model"/ (str(ts) +'scaler.pkl')
        headers = list(df.columns)
        if self.data_type == 'benign':
            scaler = StandardScaler()
            df[headers] = scaler.fit_transform(df.values)
            pickle.dump(scaler, open(str(file_path), 'wb'))
        elif self.data_type == 'attack':
            print('saved scaler used')
            scaler = pickle.load(open(str(file_path), 'rb'))
            df[headers] = scaler.transform(df.values)
        return df

    @staticmethod
    def get_time_scale_df(time_scale_features, time_scale):
        df = pd.DataFrame()
        for key in time_scale_features:
            header = str(time_scale) + '_' + str(key)
            df[header] = pd.Series(time_scale_features[key])
        return df

    def save_device_traffic_attributes(self):
        """Takes in one single device instance"""
        # rows = zip(first_time_scale_cols, second_time_scale_cols)
        file_path = Path(r"C:\Users\amith\Documents\Uni\Masters\device_attributes") / self.device_name / "normalised"
        df_first_time_scale, df_second_time_scale = self.get_time_scale_df(self.first_time_scale_features, self.time_scales[0]), self.get_time_scale_df(self.second_time_scale_features, self.time_scales[1])
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
        save_feature_df = self.device_folder / 'features'

        # df_first_time_scale.to_csv(str(file_path) + "second.csv")
        # Compute z-scores for attributes
        z_score_cols = []
        def z_score(cols, df, org_df):
            for col in cols:
                col_zscore = col + '_zscore'
                z_score_cols.append(col_zscore)
                df[col_zscore] = (org_df[col] - org_df[col].mean()) / org_df[col].std()
            return df


        df_first_time_scale = df_first_time_scale.fillna(0)
        df_second_time_scale = df_second_time_scale.fillna(0)
        # df_first_time_scale.to_csv(str(save_feature_df / (str(self.time_scales[0]) + self.data_type + "s.csv")))
        # df_second_time_scale.to_csv(str(save_feature_df / (str(self.time_scales[1]) + self.data_type + "s.csv")))
        df_first_time_scale = self.normalise_time_scale(df_first_time_scale, self.time_scales[0])
        df_first_time_scale.to_csv(str(file_path / str(self.time_scales[0]))+self.data_type+".csv")
        df_second_time_scale = self.normalise_time_scale(df_second_time_scale, self.time_scales[1])
        df_second_time_scale.to_csv(str(file_path / str(self.time_scales[1]))+self.data_type+".csv")
        # df_first_time_zscore = z_score(list(df_first_time_scale.columns), pd.DataFrame(), df_first_time_scale)
        # df_second_time_zscore = z_score(list(df_second_time_scale.columns), pd.DataFrame(), df_second_time_scale)

        # df_first_time_zscore.to_csv(str(file_path / str(self.time_scales[0]))+self.data_type+".csv")
        # df_second_time_zscore.to_csv(str(file_path / str(self.time_scales[1]))+self.data_type+".csv")

        # df_first_time_scale.to_csv(str(file_path))
        # test = self.clean_dataset(df_second_time_zscore)
        # df_first_time_scale = clean_dataset(df_first_time_scale)


    def create_clustering_model(self):
        """TODO: Assign the timescale dataset to a variable i.e. which timescale dataset is being trained"""
        time_scale_files = self.get_time_scale_files()
        p = Pool(len(time_scale_files))
        # print('time_scale_files', time_scale_files)
        # p.map(self.train_time_scale_model, time_scale_files)

        if self.experiment != 'all':
            self.train_time_scale_model(self.experiment)
        else:
            for file in time_scale_files:
                self.train_time_scale_model(file)

    def train_time_scale_model(self, file):
        """Gets csv and creates clustering model for time_scale features"""
        print('training on', file)
        dataset = self.training_data / file
        df = pd.read_csv(str(dataset))
        if self.train_type == 'find_k':
            self.find_k(df, str(file)[:-4])
        else:
            self.save_model(df, file)

    def get_time_scale_files(self):
        time_scale_files = []
        for file in self.training_data.iterdir():
            time_scale_files.append(file.name)
        return time_scale_files

    def train_model(self, df):
        """ Clustering model instantiated
        df: csv in pd.DataFrame format
        inspection: optional argument to return cluster model for anomaly detection
        """
        data = df.values
        if self.model_function == 'anomaly_detection':
            model = self.km_model.fit(data)
            return model
        else:
            clusters = self.km_model.fit_predict(data)
            centroids = self.km_model.cluster_centers_
            # df['cluster'] = self.km_model.labels_
            # dist = sdist.cdist(data, centroids)
            # print(dist)
            # self.km_model = self.km_model.fit(data)
            print("Shape of data", centroids.shape)
            # dimensionality = centroids.shape[1]
            return self.find_cluster_boundary(data, centroids, clusters)

    def save_model(self, df, file):
        cluster_boundary, cluster_distances = self.train_model(df)
        file_name = self.device_folder / "kmeans-model" /str(file)[:-4]
        ar = kl.archives.dir_archive(name=file_name, serialized=True, cached=True, protocol=4)
        ar['cluster_model'] = self.km_model
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
        self.time_scale_anomalies = {time_scale: {'anomalies':[], 'anomaly_index':[]} for time_scale in self.benign_model}
        p = Pool(len(self.benign_model.keys()))
        # p.map(self.inspect_traffic, self.benign_model.keys())

        for time_scale in self.benign_model:
            self.inspect_traffic(time_scale)
        self.save_anomalies()
        self.validate_anomalies()

        # print(self.time_scale_anomalies['250s'])
        # print(self.time_scale_anomalies['500s'])

    def inspect_traffic(self, time_scale):
        """Cluster boundary for time_scale model are the arguments"""
        print("inspecting", time_scale)
        benign_data = self.device_folder / "Benign" / (str(time_scale) + '.csv')
        attack_file = self.device_folder/ "Attack"/ (str(time_scale) + '.csv')

        benign_df = pd.read_csv(str(benign_data))
        test = KMeans(n_clusters=6)
        # test_x = test.fit(benign_df.values)
        inspect_df = pd.read_csv(str(attack_file))
        inspect_data = inspect_df.values
        attack_centroids = test.fit_predict(inspect_data)
        print("attack", test.cluster_centers_.shape)
        benign_cluster_model = self.benign_model[time_scale]['cluster_model']
        # self.validate_model(benign_cluster_model, time_scale)
        print(attack_file)
        # X_test = benign_cluster_model.transform(inspect_data)
        print("passed")
        results = benign_cluster_model.predict(inspect_data)
        cluster_points_distances = self.find_cluster_boundary(inspect_data, benign_cluster_model.cluster_centers_, results)
        cluster_map = pd.DataFrame()
        cluster_map['data_index'] = inspect_df.index.values
        cluster_map['cluster'] = results
        cluster_map.to_csv(str(self.device_folder/time_scale)+"index_data_clusters.csv")
        cluster_boundary = self.benign_model[time_scale]['cluster_boundary']
        self.find_anomalies(time_scale, cluster_boundary, cluster_points_distances, cluster_map)

    def find_anomalies(self, time_scale, cluster_boundary, cluster_distances, cluster_map):
        # print(time_scale, 'boundaries', cluster_boundary)
        for centroid in cluster_distances:
            # print(time_scale, 'distances',  cluster_distances[centroid])
            centroid_data_index = list(cluster_map[cluster_map.cluster == centroid].data_index.values)
            i = 0
            for instance in cluster_distances[centroid]:
                if instance >= cluster_boundary[centroid]:
                    self.time_scale_anomalies[time_scale]['anomalies'].append(instance)
                    self.time_scale_anomalies[time_scale]['anomaly_index'].append(centroid_data_index[i])
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
        if self.model_function == 'validate':
            time_scales = ['250s', '500s']
        else:
            time_scales = list(self.time_scale_anomalies.keys())
        time_scale_anomaly_index = {time_scale: [] for time_scale in time_scales}
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
            for time_scale in time_scale_anomaly_index:
                time_scale_anomaly_index[time_scale].extend(ts_index_range(attack_time, time_scale))

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
        tp_anomalies = []
        meta_data_keys = list(self.attack_metadata.keys())
        for ts in self.anomaly_timestamp:
            print(ts, self.anomaly_timestamp[ts])
            for anomaly in self.anomaly_timestamp[ts]:
                i = 0
                for attack_ts in global_attack_timestamp:
                    if attack_ts[0] <= anomaly <= attack_ts[1]:
                        tp += 1
                        tp_anomalies.append((int(anomaly), ts))
                        print(self.attack_metadata[meta_data_keys[i]]['attack_type'])
                    i += 1
        # print(tp_anomalies)
        # print(len(tp_anomalies))


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
        for time_scale in self.time_scale_anomalies:
            # total_device_time = self.get_total_device_time(time_scale)
            # print(time_scale, 'total duration', total_device_time)
            # Data structure to store anomaly timestamp
            self.anomaly_timestamp[time_scale] = []
            for centroid in self.time_scale_anomalies[time_scale]:
                for anomaly_index in self.time_scale_anomalies[time_scale][centroid]:
                    anomaly_timestamp = (anomaly_index + 1) * int(time_scale[:-1])
                    self.anomaly_timestamp[time_scale].append(anomaly_timestamp)
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
        for time_scale in saved_model.iterdir():
            if len(time_scale.name) > 7:
                continue
            db = saved_model / time_scale.name
            d = kl.archives.dir_archive(name=db, serialized=True)
            d.load('cluster_boundary')
            d.load('cluster_distances')
            d.load('cluster_model')
            # time_scale_boundary[time_scale.name] = d['cluster_boundary']
            self.benign_model[time_scale.name] = {}
            self.benign_model[time_scale.name]['cluster_model'] = d['cluster_model']
            self.benign_model[time_scale.name]['benign_distances'] = d['cluster_distances']
            self.benign_model[time_scale.name]['benign_centroids'] = d['cluster_model'].cluster_centers_
            self.benign_model[time_scale.name]['cluster_boundary'] = d['cluster_boundary']
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
        cols = ['P1','P2']
        print('finding K', file)
        x = df.values
        K = range(2,15)
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
        plt.show()
        # print(inertia)

    def clean_dataset(self, df):
        df.dropna(inplace=True)
        indices_to_keep = ~df.isin([np.nan, np.inf, -np.inf]).any(1)
        return df[indices_to_keep].astype(np.float64)

