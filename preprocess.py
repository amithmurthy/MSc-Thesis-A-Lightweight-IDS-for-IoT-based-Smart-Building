from sklearn.decomposition import PCA, TruncatedSVD
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.pipeline import Pipeline
import csv
# import tensorflow as tf
from pathlib import Path
import pandas as pd
import numpy as np
""" Functions for normalising data """


class ModelDevice:

    def __init__(self, device_traffic):
        self.device_traffic = device_traffic
        self.features = ['local_inputs_mean', 'local_inputs_std', 'local_outputs_mean', 'local_outputs_std',
                    'internet_inputs_mean',
                    'internet_inputs_std', 'internet_outputs_mean', 'internet_outputs_std']
        self.first_time_scale_features = {feature:[] for feature in self.features}
        self.second_time_scale_features = {feature:[] for feature in self.features}
        self.save_device_traffic_attributes()


    def get_time_scale_features(self, device_obj):
        flows = ['local_inputs', 'local_outputs', 'internet_inputs', 'internet_outputs']
        first_time_scale = {attr: None for attr in flows}
        second_time_scale = {attr: None for attr in flows}
        for attribute in flows:
            first_time_scale[attribute] = device_obj.create_traffic_volume_features(attribute, w_window=250)
            second_time_scale[attribute] = device_obj.create_traffic_volume_features(attribute, w_window=500)

        def get_features(time_scale_dict, time_scale_feature):
            local_input_mean, local_input_std = device_obj.get_mean_and_std(time_scale_dict['local_inputs'])
            # time_scale_feature['local_input_mean'].extend(local_input_mean)
            # time_scale_feature['local_input_std'].extend(local_input_std)
            local_output_mean, local_output_std = device_obj.get_mean_and_std(time_scale_dict['local_outputs'])
            # time_scale_feature['local_output_mean'].extend(local_output_mean)
            # time_scale_feature['local_output_std'].extend(local_output_std)
            internet_input_mean, internet_input_std = device_obj.get_mean_and_std(time_scale_dict['internet_inputs'])
            # time_scale_feature['internet_input_mean'].extend(internet_input_mean)
            # time_scale_feature['internet_input_std'].extend(internet_input_std)
            internet_output_mean, internet_output_std = device_obj.get_mean_and_std(time_scale_dict['internet_outputs'])
            # time_scale_feature['internet_output_mean'].extend(internet_output_mean)
            # time_scale_feature['internet_output_std'].extend(internet_output_std)
            return local_input_mean, local_input_std, local_output_mean, local_output_std, internet_input_mean, internet_input_std, internet_output_mean, internet_output_std

        def set_features(time_scale_feat,time_scale_feat_dict):
            for i in range(0, len(self.features)):
                time_scale_feat_dict[self.features[i]].extend(time_scale_feat[i])



        first_time_scale_feat = get_features(first_time_scale, self.first_time_scale_features)
        second_time_scale_feat = get_features(second_time_scale, self.second_time_scale_features)
        set_features(first_time_scale_feat, self.first_time_scale_features)
        set_features(second_time_scale_feat, self.second_time_scale_features)


    def clean_dataset(self, df):
        df.dropna(inplace=True)
        indices_to_keep = ~df.isin([np.nan, np.inf, -np.inf]).any(1)
        return df[indices_to_keep].astype(np.float64)


    def save_device_traffic_attributes(self):
        """Takes in one single device instance"""
        # rows = zip(first_time_scale_cols, second_time_scale_cols)
        for device_obj in self.device_traffic:
            print(device_obj)
            self.get_time_scale_features(device_obj)

        file_path = Path(r"C:\Users\amith\Documents\Uni\Masters\device_attributes") / self.device_traffic[0].device_name

        df_first_time_scale, df_second_time_scale = pd.DataFrame(), pd.DataFrame()

        first_headers = ["250_local_inputs_mean", "250_local_inputs_std", "250_local_outputs_mean",
                         "250_local_outputs_std",
                         "250_internet_inputs_mean", "250_internet_inputs_std", "250_internet_outputs_mean",
                         "250_internet_outputs_std"]
        second_headers = ["500_local_inputs_mean", "500_local_inputs_std", "500_local_outputs_mean",
                          "500_local_outputs_std",
                          "500_internet_inputs_mean", "500_internet_inputs_std", "500_internet_outputs_mean",
                          "500_internet_outputs_std"]
        # print(len(first_time_scale_cols + second_time_scale_cols))
        # df = pd.DataFrame()

        # all_features = first_time_scale_cols + second_time_scale_cols
        # print('all features len', len(all_features))
        # print("headers len", len(headers))

        for key in self.first_time_scale_features:
            try:
                # df[first_headers[i]] = pd.Series(first_time_scale_cols[i])
                header = "250_" + str(key)
                df_first_time_scale[header] = self.first_time_scale_features[key]
                # print(first_headers[i], len(first_time_scale_cols[i]))
            except ValueError as e:
                print(header)
                print(e)
        for key in self.second_time_scale_features:
            # df[second_headers[i]] = pd.Series(second_time_scale_cols[i])
            header = "500_" + str(key)
            df_second_time_scale[header] = self.second_time_scale_features[key]
            # print(second_headers[i], len(second_time_scale_cols[i]))

        df_first_time_scale.to_csv(str(file_path) + "second.csv")
        # Compute z-scores for attributes
        # cols = list(df.columns)
        z_score_cols = []
        def z_score(cols, df, org_df):
            for col in cols:
                col_zscore = col + '_zscore'
                z_score_cols.append(col_zscore)
                df[col_zscore] = (org_df[col] - org_df[col].mean()) / org_df[col].std()
            return df

        df_first_time_scale = df_first_time_scale.fillna(0)
        df_second_time_scale = df_second_time_scale.fillna(0)
        df_first_time_zscore = z_score(list(df_first_time_scale.columns), pd.DataFrame(), df_first_time_scale)
        df_second_time_zscore = z_score(list(df_second_time_scale.columns), pd.DataFrame(), df_second_time_scale)
        df_first_time_zscore.to_csv(str(file_path) + "firstzscore.csv")
        df_second_time_zscore.to_csv(str(file_path)+"secondscore.csv")
        # df_first_time_scale.to_csv(str(file_path))
        # test = self.clean_dataset(df_second_time_zscore)
        # df_first_time_scale = clean_dataset(df_first_time_scale)

        ##Find the eigen values and vectors


        x = df_first_time_scale.loc[:, first_headers].values
        x = StandardScaler().fit_transform(x)
        # print(x)
        # data = df_first_time_scale.loc[:, first_headers].values
        # pipeline = Pipeline([('scaling', StandardScaler()), ('pca', PCA())])
        # pipeline.fit_transform(data)
        # x.dropna(inplace=True)
        pca = PCA(n_components=0.95)
        X_pca = pca.fit(df_first_time_zscore)
        print(X_pca.components_)
        # X_reduced.to_csv(str(file_path))
        # write_csv_file(first_time_scale_cols + second_time_scale_cols, headers)

        print("finished saving csv")