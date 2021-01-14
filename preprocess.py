from sklearn.preprocessing import StandardScaler
import csv
from pathlib import Path
import pandas as pd
import threading
""" Functions for normalising data """


def save_device_attributes(device_obj):
    """Takes in one single device instance"""
    attributes = []
    flow_features = ['local_inputs','local_outputs','internet_inputs','internet_outputs']
    first_time_scale = {attr: None for attr in flow_features}
    second_time_scale = {attr: None for attr in flow_features}
    for attribute in flow_features:
        first_time_scale[attribute] = device_obj.create_traffic_volume_features(attribute, w_window=250)
        second_time_scale[attribute] = device_obj.create_traffic_volume_features(attribute, w_window=500)

    def get_columns(time_scale_dict):
        local_input_mean, local_input_std = device_obj.get_mean_and_std(time_scale_dict['local_inputs'])
        local_output_mean, local_output_std = device_obj.get_mean_and_std(time_scale_dict['local_outputs'])
        internet_input_mean, internet_input_std = device_obj.get_mean_and_std(time_scale_dict['internet_inputs'])
        internet_output_mean, internet_output_std = device_obj.get_mean_and_std(time_scale_dict['internet_outputs'])
        return local_input_mean, local_input_std, local_output_mean, local_output_std, internet_input_mean, internet_input_std, internet_output_mean, internet_output_std

    first_time_scale_cols = get_columns(first_time_scale)
    second_time_scale_cols = get_columns(second_time_scale)
    # rows = zip(first_time_scale_cols, second_time_scale_cols)
    file_path = Path(r"C:\Users\amith\Documents\Uni\Masters\device_attributes") / str(device_obj.device_name + ".csv")
    def write_csv_file(values, headers):
        with open(str(file_path), 'w') as f:
            writer = csv.writer(f)
            writer.writerow(header for header in headers)
            for col in values:
                for val in col:
                    writer.writerow([val])

    first_headers = ["250_local_inputs_mean", "250_local_inputs_std", "250_local_outputs_mean","250_local_outputs_std",
               "250_internet_inputs_mean", "250_internet_inputs_std", "250_internet_outputs_mean", "250_internet_outputs_std"]

    second_headers = ["500_local_inputs_mean", "500_local_inputs_std", "500_local_outputs_mean","500_local_outputs_std",
                   "500_internet_inputs_mean", "500_internet_inputs_std", "500_internet_outputs_mean","500_internet_outputs_std"]
    # print(len(first_time_scale_cols + second_time_scale_cols))
    df = pd.DataFrame()
    # all_features = first_time_scale_cols + second_time_scale_cols
    # print('all features len', len(all_features))
    # print("headers len", len(headers))
    for i in range(0, len(first_time_scale_cols)):
        try:
            df[first_headers[i]] = first_time_scale_cols[i]
        except ValueError:
            print(i)
    for i in range(0, len(second_time_scale_cols)):
        # second_headers[i]
        df[second_headers[i]] = second_time_scale_cols[i]

    # write_csv_file(first_time_scale_cols + second_time_scale_cols, headers)
    # thread1 = threading.Thread(target=write_csv_file(first_time_scale_cols,first_time_scale_headers))
    # thread2 = threading.Thread(target=write_csv_file(second_time_scale_cols,second_time_scale_headers))
    # thread1.start()
    # thread2.start()
    # thread1.join()
    # thread2.join()
    print("finished saving csv")