import csv
import shutil
import os
from itertools import zip_longest
import pandas as pd
import pandas as pd
import json
import re
import socket
import dpkt
import SEARCH_analysis1_0_d_new as SEARCH
import subprocess
import functions_SEARCH as functions
import matplotlib.pyplot as plt
import json
import numpy as np
import csv

BYTES_TO_MEGABITS = 1 / 125000  # The number of bytes in a megabit

ANALYZE_TIME = 1  # The time to analyze in seconds
INTERVAL_DURATION = 0.025  # The duration of each interval in seconds

# MAX_Y = 15  # The maximum value of the y-axis in the throughput plot in Mbps

def relocate_files():
    all_experiments_folder = os.path.join(os.getcwd(), "logs")

    for experiment_name in sorted(os.listdir(all_experiments_folder)):
        experiment_folder = os.path.join(all_experiments_folder, experiment_name)

        if not os.path.isdir(experiment_folder) or is_experiment_processed(
            experiment_folder
        ):
            continue

        new_log_data_folder = os.path.join(experiment_folder, "log_data")
        new_log_folder = os.path.join(new_log_data_folder, "log")
        new_pcap_data_folder = os.path.join(experiment_folder, "pcap_data")
        new_pcap_folder = os.path.join(new_pcap_data_folder, "pcap")

        os.makedirs(new_log_folder, exist_ok=True)
        os.makedirs(new_pcap_folder, exist_ok=True)

        counter_pcap = 1
        counter_log = 1

        # runX_S0H1_R-93_20ms_100.0mbps_memo

        for run_folder_name in sorted(os.listdir(experiment_folder)):
            if not run_folder_name.startswith("run"):
                continue

            run_folder_path = os.path.join(experiment_folder, run_folder_name)
            print(experiment_folder)
            print(run_folder_name)

            searchMode, hystartEnabled, rssi, average_ping, memo = get_info(
                run_folder_path
            )

            for folder_type in ["client", "server"]:
                folder_path = os.path.join(run_folder_path, folder_type)
                if os.path.exists(folder_path):
                    for file in sorted(os.listdir(folder_path)):

                        src_file_path = os.path.join(folder_path, file)

                        if file.endswith(".pcap") and folder_type == "server":
                            dest_file_name = f"{run_folder_name}_S{searchMode}H{hystartEnabled}_R{rssi}_{average_ping:.3f}ms_{memo}.pcap"
                            dest_file_path = os.path.join(
                                new_pcap_folder, dest_file_name
                            )
                            shutil.copy(src_file_path, dest_file_path)
                            counter_pcap += 1
                        elif file == "kern.log":
                            dest_file_name = f"{run_folder_name}_S{searchMode}H{hystartEnabled}_R{rssi}_{average_ping:.3f}ms_{memo}.log"
                            dest_file_path = os.path.join(
                                new_log_folder, dest_file_name
                            )
                            shutil.copy(src_file_path, dest_file_path)
                            counter_log += 1


def get_info(run_folder_path):
    print(run_folder_path)
    file_path = os.path.join(run_folder_path, "RUN_INFO.json")
    with open(file_path, "r") as file:
        content = json.load(file)

    memo = content["memo"]
    searchMode = int(content["searchMode"])
    hystartEnabled = int(content["hystartEnabled"])

    file_path = os.path.join(run_folder_path, "RUN_INFO.md")
    with open(file_path, "r") as file:
        content = file.read()

    rssi = re.findall(r"agrCtlRSSI:\s*(-?\d+)", content)
    rssi = float(rssi[0])

    file_path = os.path.join(run_folder_path, "client", "ping.log")
    with open(file_path, "r") as file:
        content = file.read()

    ping_times = re.findall(r"time=(\d+\.\d+) ms", content)
    ping_times = [float(time) for time in ping_times]
    average_ping = sum(ping_times) / len(ping_times)

    return [searchMode, hystartEnabled, rssi, average_ping, memo]


def extract_s_h_numbers_from_filename(file_name):
    match = re.search(r"S(\d+)H(\d+)_", file_name)
    if match:
        return int(match.group(1)), int(match.group(2))
    return None, None


def convert_pcap_to_csv_tshark(pcap_file, csv_output):
    print(f"converting {pcap_file}  to .csv")
    tcp_stream = find_desired_stream(pcap_file)
    # Define column names
    column_names = [
        "Time",
        "Source",
        "Destination",
        "Protocol",
        "Length",
        "Sequence number",
        "Ack number",
        "TSval",
        "TSecr",
        "duplicate_ack",
        "SACK",
        "CE",
    ]

    command = [
        "tshark",
        "-r",
        pcap_file,
        "-Y",
        f"tcp.stream eq {tcp_stream}",
        "-T",
        "fields",
        "-e",
        "frame.time_relative",
        "-e",
        "ip.src",
        "-e",
        "ip.dst",
        "-e",
        "ip.proto",
        "-e",
        "frame.len",
        "-e",
        "tcp.seq",
        "-e",
        "tcp.ack",
        "-e",
        "tcp.options.timestamp.tsval",
        "-e",
        "tcp.options.timestamp.tsecr",
        "-e",
        "tcp.analysis.duplicate_ack_num",
        "-e",
        "tcp.options.sack.count",
        "-e",
        "ip.dsfield.ecn",
        "-E",
        "separator=,",
        "-E",
        "occurrence=f",
    ]

    try:
        with open(csv_output, "w") as output_file:
            # Write column names as the first line
            output_file.write(",".join(column_names) + "\n")

            # Run tshark command and capture its output
            result = subprocess.run(
                command, stdout=subprocess.PIPE, check=True, text=True
            )

            # Write captured output to the CSV file
            output_file.write(result.stdout)

        # print(f"Traffic data from '{pcap_file}' has been saved to '{csv_output}'")
    except subprocess.CalledProcessError as e:
        print(f"Error converting '{pcap_file}':", e)


def find_packet_count(pcap_file, tcp_stream):
    try:
        # Use tshark to count the number of packets in the TCP stream
        tshark_cmd = [
            "tshark",
            "-r",
            pcap_file,
            f"tcp.stream eq {tcp_stream}",
        ]
        tshark_result = subprocess.run(
            " ".join(tshark_cmd),
            shell=True,
            stdout=subprocess.PIPE,
            check=True,
            text=True,
        )

        # Count lines (packets) using Python
        pkt_num = len(tshark_result.stdout.splitlines())

        return pkt_num
    except subprocess.CalledProcessError as e:
        print(f"Error counting packets in '{pcap_file}':", e)

    return None


def find_desired_stream(pcap_file):
    Max_ITER = 10
    Min_Num_pkt = 5000
    for i in range(1, Max_ITER + 1):
        pkt_num = find_packet_count(pcap_file, i)
        if pkt_num is not None and pkt_num >= Min_Num_pkt:
            print(i)
            return i  # Return the stream number

    return None  # No suitable stream found


def convert_pcap_to_csv(pcap_file, csv_output):

    with open(pcap_file, "rb") as f, open(csv_output, "w", newline="") as csvfile:
        pcap = dpkt.pcap.Reader(f)
        writer = csv.writer(csvfile)
        # Write the CSV header
        writer.writerow(
            [
                "Time",
                "Source",
                "Destination",
                "Protocol",
                "Length",
                "Sequence Number",
                "Ack Number",
                "Window Size",
            ]
        )

        start_time = None

        for timestamp, buf in pcap:
            if start_time is None:
                start_time = timestamp

            if timestamp - start_time > ANALYZE_TIME:
                break

            eth = dpkt.ethernet.Ethernet(buf)
            # Make sure this is an IP packet
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            ip = eth.data

            # Filter for TCP packets
            if isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data
                src_ip = socket.inet_ntoa(ip.src)
                dst_ip = socket.inet_ntoa(ip.dst)
                protocol = "TCP"
                length = ip.len
                seq_num = tcp.seq
                ack_num = tcp.ack
                window_size = tcp.win

                # Write packet information to the CSV file
                writer.writerow(
                    [
                        timestamp,
                        src_ip,
                        dst_ip,
                        protocol,
                        length,
                        seq_num,
                        ack_num,
                        window_size,
                    ]
                )


def convert_pcap_to_csv_multiple(pcap_data_folder):
    pcap_folder = os.path.join(pcap_data_folder, "pcap")
    for pcap_file_name in os.listdir(pcap_folder):
        if pcap_file_name.endswith(".pcap"):
            pcap_file_path = os.path.join(pcap_folder, pcap_file_name)
            csv_file_path = os.path.join(
                pcap_data_folder, pcap_file_name.replace(".pcap", ".csv")
            )
            convert_pcap_to_csv(pcap_file_path, csv_file_path)


def convert_log_to_csv_multiple(log_data_folder):
    if not os.path.exists(log_data_folder):
        os.makedirs(log_data_folder)

    # Set the log files folder path
    log_file_folder = os.path.join(log_data_folder, "log")

    for file_name in sorted(os.listdir(log_file_folder)):

        match = re.search(r"S(\d)H(\d)", file_name)

        S = int(match.group(1))
        H = int(match.group(2))

        SEARCH_DATA = 0
        BBR_DATA = 0
        DEFAULT_TRADITIONAL_TCP = 0

        if S == 1:
            SEARCH_DATA = 1
        if H == 0:
            DEFAULT_TRADITIONAL_TCP = 1

        log_file_path = os.path.join(log_file_folder, file_name)

        csv_file_path = os.path.join(log_data_folder, file_name[:-4] + ".csv")

        print(csv_file_path)

        if SEARCH_DATA == 1:

            lines = functions.open_file(log_file_path)

            lines_reverse = lines[::-1]

            for line in lines_reverse:
                if "total_byte_acked" in line:
                    total_byte_acked = int(
                        line.split("total_byte_acked")[1].split("]")[0]
                    )
                    if total_byte_acked > 1000:
                        if "flow pointer:" in line:
                            flow_pointer_value = line.split("flow pointer: ")[1].split(
                                "]"
                            )[0]
                            break

            # Extract data from log file
            # each_acked, now, ss_status, lost, sentB, ackedB, cwnd, ssthresh, rtt = functions.find_data_new(lines, flow_pointer_value)
            (
                each_acked,
                now,
                ss_status,
                lost,
                cwnd,
                ssthresh,
                rtt,
                total_delv_MB,
                total_retrans,
                now_time_s_from_zero,
                current_wind_MB,
                prev_wind_MB,
                norm,
                search_ex_time_s,
            ) = functions.find_data_both(lines, flow_pointer_value)

            # Set the start time of flow to zero
            start_time_zero = functions.adjust_timestamps_to_start_at_zero(now)  # sec

            lists = [
                each_acked,
                now,
                ss_status,
                lost,
                cwnd,
                ssthresh,
                rtt,
                total_delv_MB,
                start_time_zero,
                total_retrans,
                now_time_s_from_zero,
                current_wind_MB,
                prev_wind_MB,
                norm,
                search_ex_time_s,
            ]

            variable_header = [
                "each_delv_MB",
                "now_s",
                "ss_status",
                "lost_pkt",
                "cwnd_MB",
                "ssthresh_pkt",
                "rtt_s",
                "total_delv_MB",
                "start_time_zero_s",
                "total_retrans_pkt",
                "search_time_s",
                "current_wind_MB",
                "prev_wind_MB",
                "norm",
                "search_ex_time_s",
            ]

            with open(csv_file_path, "w+") as f:
                writer = csv.writer(f)
                writer.writerow(variable_header)
                for values in zip_longest(*lists):
                    writer.writerow(values)

        print("Done")

        if BBR_DATA == 1:

            lines = functions.open_file(log_file_path)

            lines_reverse = lines[::-1]

            for line in lines_reverse:
                if "byte_acked" in line:
                    total_byte_acked = int(line.split("byte_acked")[1].split("]")[0])
                    if total_byte_acked > 1000:
                        if "flow pointer:" in line:
                            flow_pointer_value = line.split("flow pointer: ")[1].split(
                                "]"
                            )[0]
                            break

            # Extract data from log file
            # each_acked, now, ss_status, lost, sentB, ackedB, cwnd, ssthresh, rtt = functions.find_data_new(lines, flow_pointer_value)
            (
                now_time_s_from_zero,
                bbr_state,
                each_acked,
                each_sent,
                rtt_s,
                cwnd,
                est_bw,
                loss_pkt,
                total_retrans_pkt,
                byte_acked,
                byte_sent,
            ) = functions.find_data_bbr(lines, flow_pointer_value)

            lists = [
                now_time_s_from_zero,
                bbr_state,
                each_acked,
                each_sent,
                rtt_s,
                cwnd,
                est_bw,
                loss_pkt,
                total_retrans_pkt,
                byte_acked,
                byte_sent,
            ]

            variable_header = [
                "start_time_zero_s",
                "bbr_state",
                "each_delv_MB",
                "each_sent_MB",
                "rtt_s",
                "cwnd_MB",
                "est_bw",
                "lost_pkt",
                "total_retrans_pkt",
                "total_delv_MB",
                "total_sent_MB",
            ]

            with open(csv_file_path, "w+") as f:
                writer = csv.writer(f)
                writer.writerow(variable_header)
                for values in zip_longest(*lists):
                    writer.writerow(values)

            print("Done")

        if DEFAULT_TRADITIONAL_TCP == 1:
            # Loop over the log files

            lines = functions.open_file(log_file_path)

            lines_reverse = lines[::-1]

            for line in lines_reverse:
                if "total_byte_acked" in line:
                    byte_acked = int(line.split("total_byte_acked")[1].split("]")[0])
                    if byte_acked > 1000:
                        if "flow pointer:" in line:
                            flow_pointer_value = line.split("flow pointer: ")[1].split(
                                "]"
                            )[0]
                            break

            # Extract data from log file
            (
                each_acked,
                now,
                ss_status,
                lost,
                cwnd,
                ssthresh,
                rtt,
                total_delv_MB,
                total_retrans,
            ) = functions.find_data_new(lines, flow_pointer_value)
            # Set the start time of flow to zero
            start_time_zero = functions.adjust_timestamps_to_start_at_zero(now)  # sec

            data = zip(
                each_acked,
                now,
                ss_status,
                lost,
                cwnd,
                ssthresh,
                rtt,
                start_time_zero,
                total_delv_MB,
                total_retrans,
            )
            variable_header = [
                "each_delv_MB",
                "now_s",
                "ss_status",
                "lost_pkt",
                "cwnd_MB",
                "ssthresh_pkt",
                "rtt_s",
                "start_time_zero_s",
                "total_delv_MB",
                "total_retrans_pkt",
            ]

            functions.write_data_to_csv_float(csv_file_path, data, variable_header)

            print("Done")


def parse_types(pcap_data_folder):
    types = {}
    all_paths = []

    for file_name in os.listdir(pcap_data_folder):
        if not file_name.endswith(".csv"):
            continue
        type_id = extract_s_h_numbers_from_filename(file_name)
        if type_id not in types:
            types[type_id] = []

        file_path = os.path.join(pcap_data_folder, file_name)
        types[type_id].append(file_path)
        all_paths.append(file_path)

    for type_id, file_paths in types.items():
        if type_id == (None, None):
            continue
        output_excel_path = os.path.join(
            pcap_data_folder, f"S{type_id[0]}H{type_id[1]}.xlsx"
        )
        create_excel_info(file_paths, output_excel_path)

    output_excel_path = os.path.join(pcap_data_folder, "All_types.xlsx")
    create_excel_info(all_paths, output_excel_path)


def create_excel_info(file_paths, output_excel_path):
    n_intervals = int(ANALYZE_TIME / INTERVAL_DURATION)  # Number of intervals

    all_average_throughputs = []  # To store average throughput from each file
    max_range = 0  # To store the max range of intervals

    rssis = []  # To store the rssi values
    pings = []  # To store the ping values

    # Initialize dictionary to store throughputs for each interval across all files
    interval_throughputs = {i: [] for i in range(int(ANALYZE_TIME / INTERVAL_DURATION))}

    # Process each file
    for file_path in file_paths:
        data = pd.read_csv(file_path)

        # Find the start time and adjust to a 2-second window from the first data point
        start_time = data["Time"].min()
        end_time = start_time + ANALYZE_TIME

        filtered_data = data[(data["Time"] >= start_time) & (data["Time"] <= end_time)]

        # Calculate average throughput for the file
        if not filtered_data.empty:
            total_length = filtered_data["Length"].sum()  # Total length of packets
            average_throughput = (
                total_length / ANALYZE_TIME
            )  # Divide by the window size for average throughput
            all_average_throughputs.append(average_throughput)

            # Calculate intervals based on the shifted time
            intervals = np.linspace(start_time, end_time, n_intervals + 1)
            filtered_data["Interval"] = pd.cut(
                filtered_data["Time"], bins=intervals, labels=False, right=False
            )

            # Calculate throughput for each interval
            for i in range(n_intervals):
                interval_data = filtered_data[filtered_data["Interval"] == i]
                if not interval_data.empty:
                    interval_length = interval_data["Length"].sum()
                    interval_throughputs[i].append(interval_length / INTERVAL_DURATION)

        # Extract rssi and ping values
        match = re.search(r"R(-\d+\.\d+)_(\d+\.\d+)ms", file_path)

        if match:
            rssi = float(match.group(1))
            ping = float(match.group(2))
            rssis.append(rssi)
            pings.append(ping)

    # Calculate overall metrics
    overall_avg_throughput = np.mean(all_average_throughputs) * BYTES_TO_MEGABITS
    overall_std_throughput = np.std(all_average_throughputs) * BYTES_TO_MEGABITS

    # Get max throughput for all intervals
    for i in range(n_intervals):
        max_range = max(
            max_range, (np.array(interval_throughputs[i]) * BYTES_TO_MEGABITS).max()
        )

    # Calculate metrics for each interval and prepare interval range labels
    interval_avgs = []
    interval_stds = []
    interval_ranges = []
    for i in range(n_intervals):
        interval_avgs.append(
            np.mean(interval_throughputs[i]) * BYTES_TO_MEGABITS
            if interval_throughputs[i]
            else 0
        )
        interval_stds.append(
            np.std(interval_throughputs[i]) * BYTES_TO_MEGABITS
            if interval_throughputs[i]
            else 0
        )
        # Format the interval range strings without 's' and with 3 decimal places
        interval_ranges.append(
            f"{i*INTERVAL_DURATION:.3f}-{(i+1)*INTERVAL_DURATION:.3f}"
        )

    # Save to Excel
    with pd.ExcelWriter(output_excel_path, engine="openpyxl") as writer:
        # Overall stats
        df_overall = pd.DataFrame(
            {
                "Average Throughput": overall_avg_throughput,
                "Throughput Standard Deviation": overall_std_throughput,
                "Max Range": max_range,
                "Average RSSI": np.mean(rssis),
                "RSSI Standard Deviation": np.std(rssis),
                "Average Ping": np.mean(pings),
                "Ping Standard Deviation": np.std(pings),
            },
            index=[0],
        )
        df_overall.to_excel(writer, sheet_name="Overall", index=[False])

        # Interval stats
        df_intervals = pd.DataFrame(
            {
                "Interval": range(n_intervals),
                "Interval Range": interval_ranges,
                "Average Throughput": interval_avgs,
                "Standard Deviation": interval_stds,
            }
        )
        df_intervals.to_excel(writer, sheet_name="Intervals", index=False)


def calculate_average_throughput(file_path):
    try:
        df = pd.read_csv(file_path)

        if df.empty:
            print(
                f"Warning: The file {file_path} is empty or not in the expected format."
            )
            return -1

        total_size = df["Length"].sum()
        duration = df["Time"].max() - df["Time"].min()

        if duration <= 0:
            return -1

        average_throughput = total_size / duration
        return average_throughput
    except Exception as e:
        print(f"Error processing file {file_path}: {e}")
        return -1


def calculate_average_throughput_multiple_files(folder_path):
    numFiles = 0
    total_throughput = 0

    for file_name in os.listdir(folder_path):
        file_path = os.path.join(folder_path, file_name)
        if file_name.endswith(".csv"):
            throughput = calculate_average_throughput(file_path) * BYTES_TO_MEGABITS
            file_path = file_path[:-4]
            new_name_file_path = f"_{file_path}{throughput:.3f}mbps.csv"
            os.rename(file_path, new_name_file_path)
            if throughput >= 0:
                numFiles += 1
                total_throughput += throughput

    average_throughput = -1
    if numFiles > 0:
        average_throughput = total_throughput / numFiles

    return average_throughput


def is_csv_file(file_name):
    return file_name.endswith(".csv")


def calculate_and_write_averages(folder_path):
    file_names = os.listdir(folder_path)
    csv_files = filter(is_csv_file, file_names)

    # Create a list of tuples containing (S number, H number, file name)
    files_with_numbers = [(extract_s_h_numbers_from_filename(f), f) for f in csv_files]

    # Filter out files where S and H numbers couldn't be extracted
    files_with_numbers = [
        (s, h, f) for (s, h), f in files_with_numbers if s is not None and h is not None
    ]

    # Sort files first by S number, then by H number
    sorted_files = sorted(files_with_numbers, key=lambda x: (x[0], x[1]))

    averages_file_path = os.path.join(folder_path, "averages.txt")

    current_batch_s = current_batch_h = None
    batch_files = []

    with open(averages_file_path, "w") as averages_file:
        for s, h, file_name in sorted_files:
            # Start a new batch if S or H number changes
            if s != current_batch_s or h != current_batch_h:
                if batch_files:
                    write_batch_average(batch_files, averages_file, folder_path)
                current_batch_s, current_batch_h = s, h
                batch_files = []

            batch_files.append(file_name)

        # Process the last batch
        if batch_files:
            write_batch_average(batch_files, averages_file, folder_path)


def write_batch_average(batch_files, averages_file, folder_path):
    S, H = extract_s_h_numbers_from_filename(batch_files[0])
    total_throughput = 0
    num_files = 0
    for file_name in batch_files:
        file_path = os.path.join(folder_path, file_name)
        if os.path.isfile(file_path):  # Ensure it's a file
            throughput = calculate_average_throughput(file_path)
            total_throughput += throughput
            num_files += 1

    if num_files > 0:
        average_throughput = (total_throughput / num_files) * BYTES_TO_MEGABITS
        averages_file.write(f"S{S}H{H}: {average_throughput}\n")
    else:
        averages_file.write("No valid data in this batch\n")


def write_info(folder_path):
    average_throughput = (
        calculate_average_throughput_multiple_files(folder_path) * BYTES_TO_MEGABITS
    )  #
    text_file_path = os.path.join(folder_path, "info.txt")

    with open(text_file_path, "w") as output_file:
        output_file.write(f"Average Throughput: {average_throughput} mbps\n")


def is_experiment_processed(experiment_folder):
    marker_file_path = os.path.join(experiment_folder, "processed.txt")
    return os.path.exists(marker_file_path)


def mark_experiment_processed(experiment_folder):
    marker_file_path = os.path.join(experiment_folder, "processed.txt")
    with open(marker_file_path, "w") as f:
        f.write("Processed")


def plot_sliding_window_throughput(csv_file_path, throughput_image_path):
    print(f"Plotting Wireshark-style throughput for {csv_file_path}")

    df = pd.read_csv(csv_file_path)
    df["Length"] = df["Length"] * BYTES_TO_MEGABITS  # Convert to Megabits

    window_size = 1  # 1 second window
    time = df["Time"].values
    sizes = df["Length"].values
    n = len(df)

    throughput_data = []
    sum_packet_sizes = 0.0
    start_index = 0

    interval_y = None

    # Get parent dir of csv file
    parent_dir = os.path.dirname(csv_file_path)
    overall_xlsx = os.path.join(parent_dir, "All_types.xlsx")

    if os.path.exists(overall_xlsx):
        # Read standard deviation from excel file
        interval_df = pd.read_excel(overall_xlsx, sheet_name="Intervals")
        interval_x = interval_df["Interval"].values * INTERVAL_DURATION
        interval_y = interval_df["Standard Deviation"].values
        max_y = (
            pd.read_excel(overall_xlsx, sheet_name="Overall")["Max Range"].max()
            if MAX_Y is None
            else MAX_Y
        )

    for i in range(n):
        while time[i] - time[start_index] > window_size:
            sum_packet_sizes -= sizes[start_index]
            start_index += 1

        sum_packet_sizes += sizes[i]
        current_window_size = min(window_size, time[i] - time[start_index])
        throughput = (
            sum_packet_sizes / current_window_size if current_window_size > 0 else 0
        )
        throughput_data.append((time[i] - time[0], throughput))

    times, throughputs = zip(*throughput_data)

    plt.figure(figsize=(15, 8))
    plt.plot(times, throughputs, drawstyle="steps-post")
    plt.ylim(0, max_y)
    plt.xlabel("Time (s)")
    plt.ylabel("Throughput (Mbps)")
    plt.title("Throughput over Time (1-second sliding window)")
    plt.grid(True)

    if interval_y is not None:
        # Map throughput to standard deviation
        throughputs = np.array(throughputs)
        interval_y = np.array(interval_y)
        interval_y = np.interp(throughputs, interval_x, interval_y) / 2
        plt.fill_between(
            times,
            (throughputs - interval_y).clip(0),
            throughputs + interval_y,
            alpha=0.15,
        )

    plt.savefig(throughput_image_path, dpi=300)
    plt.close()
    print("Plot completed")


def plot_throughput_multiple_files(folder_path):
    for file_name in os.listdir(folder_path):
        file_path = os.path.join(folder_path, file_name)
        if file_name.endswith(".csv"):
            image_path = os.path.join(folder_path, file_name.replace(".csv", ".png"))
            plot_sliding_window_throughput(file_path, image_path)


def convert_files():
    all_experiments_folder = os.path.join(os.getcwd(), "logs")

    for experiment_name in sorted(os.listdir(all_experiments_folder)):
        experiment_folder = os.path.join(all_experiments_folder, experiment_name)

        if not os.path.isdir(experiment_folder):
            continue

        log_data_folder = os.path.join(experiment_folder, "log_data")
        pcap_data_folder = os.path.join(experiment_folder, "pcap_data")

        os.makedirs(log_data_folder, exist_ok=True)
        os.makedirs(pcap_data_folder, exist_ok=True)

        if not os.path.isdir(experiment_folder) or is_experiment_processed(
            experiment_folder
        ):
            continue

        # convert_log_to_csv_multiple(log_data_folder)
        convert_pcap_to_csv_multiple(pcap_data_folder)
        calculate_and_write_averages(pcap_data_folder)
        parse_types(pcap_data_folder)
        plot_throughput_multiple_files(pcap_data_folder)
        # SEARCH.runAnalysis(experiment_folder)
        mark_experiment_processed(experiment_folder)


def main():
    relocate_files()
    convert_files()


if __name__ == "__main__":
    main()
