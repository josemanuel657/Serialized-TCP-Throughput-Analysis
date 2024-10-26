"""Python version
'3.8.17 (default, Jul  5 2023, 20:44:21) [MSC v.1916 64 bit (AMD64)]'
Version info.
sys.version_info(major=3, minor=8, micro=17, releaselevel='final', serial=0)
"""

import functions_SEARCH
import os
import numpy as np
import pandas as pd
import shutil
import re
import csv
import matplotlib.pyplot as plt
import time

######################################################################
# SEARCH1.0d
# This code uses the SEARCH algorithm to find the best exit point
# (x_ex) based on Linux log data. To do this, the code approximate
# the delivered bytes of the current window and delivered byte window
# shifted back by current RTT and repeat the same process to find the
# optimal exit point. This code also finds the packet loss point, CE
# flag point, throughput and one_way delay changes from the csv file
# that contains the pcap file information.

# INPUT: the log data and pcap data as a several csv files

# OUTPUT: 'x_dp', 'success','x_ex_approx', 'x_cg_approx', 'throughput',
# 'one_way delay', 'x_ce_ecn_flag' for all csv files

############    PARAMETERS    #################
def runAnalysis(cwd):

    satellite_type = "viasat"  # 'viasat' or 'starlink' or 'lte'

    if satellite_type == "viasat":

        # Viasat One_way delay parameters
        FIRST_DESIRED_LATENCY = (
            1200  # the first limit on FL latency to help for finding the x_cg
        )
        SECOND_DESIRED_LATENCY = 300  # backward on FL latency after finding FIRST_DESIRED_LATENCY to determine the x_cg

        # SEARCH parameters
        PERIOD_CONSTANT = 2  # in seconds, Constant for all cases (WINDOW =~ 3.5 * min_RTT)

    elif satellite_type == "starlink":

        # Starlink One_way delay parameters
        FIRST_DESIRED_LATENCY = (
            60  # the first limit on FL latency to help for finding the x_cg
        )
        SECOND_DESIRED_LATENCY = 15  # backward on FL latency after finding FIRST_DESIRED_LATENCY to determine the x_cg

        # SEARCH parameters
        PERIOD_CONSTANT = (
            0.2  # in seconds, Constant for all cases (WINDOW =~ 3.5 * min_RTT)
        )

    elif satellite_type == "lte":
        # Starlink One_way delay parameters
        FIRST_DESIRED_LATENCY = (
            116  # the first limit on FL latency to help for finding the x_cg
        )
        SECOND_DESIRED_LATENCY = 28  # backward on FL latency after finding FIRST_DESIRED_LATENCY to determine the x_cg

        # SEARCH parameters
        PERIOD_CONSTANT = (
            0.2  # in seconds, Constant for all cases (WINDOW =~ 3.5 * min_RTT)
        )

    # One_way delay and throughput parameter
    SERVER_IP = "130.215.28.249"  # specific source IP address used to filter the data from the CSV files of pcap data
    # SERVER_IP = '173.76.103.211'

    # Condition
    SET_MIN_RTT = "initial_rtt"  # find min_rtt from log file to set PERIOD and WINDOW_SIZE:
    # 'custom_min_rtt': min_rtt in whole data, 'initial_rtt': the first rtt,
    # 'custom_min_rtt_slow_start': min_rtt during slow start phase (before packet loss),
    # 'constant_min_rtt': set the predefined min_rtt for all cases

    # SEARCH parameters
    WS_TIME_VALUES = [
        3.5
    ]  # coefficient of min_rtt to find the WINDOW_SIZE for approximation
    THRESH_VALUES = [0.35]  # threshold on norm graph to find the optimal exit point
    BIN_NUMS = [10]  # The number of bin for each window

    # Set congestion point manually
    X_CG_MANUAL = None

    # Throughput parameters
    INTERVAL = 1.0  # in second (size of window for calculating throughput)
    if satellite_type != "viasat":
        INTERVAL = 0.05

    THROUGHPUT_WINDOW_SIZE = None  # in second (size of sliding window for calculating throughput) (viasat = 6, starlink = 0.5)
    THROUGHPUT_SLIDING_WINDOW = (
        None  # in second (slide size for sliding window) (viasat = 0.6, starlink = 0.05)
    )

    # Script parameters
    FOLDER_NAME = os.path.join("log_data")  # folder contained csv files of log data
    PCAP_FOLDER_NAME = os.path.join("pcap_data")  # folder contained csv files of pcap data


    ############    INPUT    #################
    # Get the current working directory

    # Set the csv files folder path
    csv_file_folder = os.path.join(cwd, FOLDER_NAME)
    print(csv_file_folder)
    PCAP_FOLDER_NAME = os.path.join(cwd, PCAP_FOLDER_NAME)
    print(PCAP_FOLDER_NAME)

    # Find the number of csv files with  iterating through a folder and count the number of files
    num_files = 0

    for filename in os.listdir(csv_file_folder):
        if filename.endswith(".csv") and re.match(r"log_data\d+\.csv", filename):
            num_files += 1

    # Iterate through sensitivity values for each variable
    for WS_TIME in WS_TIME_VALUES:
        for BIN_N in BIN_NUMS:
            for THRESH in THRESH_VALUES:
                file_vars = (
                    []
                )  # list to save the variables of test for each csv file of log data
                result_data = (
                    []
                )  # list to save packet loss and at capacity points for each csv file of log data
                VARIABLE_FILE = f"variables_{BIN_N}.csv"  # csv file name to store the variables of test (x_ex, x_cg, ...)
                folder_name = f"S1d_ws_t_{WS_TIME}_bin_{BIN_N}_thresh_{THRESH}"
                # Create a directory for saving results
                result_folder = os.path.join(cwd, folder_name)
                os.makedirs(result_folder, exist_ok=True)
                # Loop over the csv files
                for case in range(1, num_files + 1):
                    print(case)
                    case_removed = [20, 22, 23, 25]
                    if satellite_type == "lte" and case in case_removed:
                        continue
                    # Load the data file
                    file_name = f"log_data{case}.csv"
                    # Join the directory path with the file name
                    address_csv = os.path.join(cwd, FOLDER_NAME, file_name)
                    # Read the csv file of log data
                    data = functions_SEARCH.read_csv_data(address_csv)
                    ############    ESSENTIAL DATA    #################
                    pkt_loss = [float(row["lost_pkt"]) for row in data]
                    cwnd = np.asarray([float(row["cwnd_MB"]) for row in data])
                    rtt_s = np.asarray([float(row["rtt_s"]) for row in data])
                    rtt = np.asarray(rtt_s) * 1e3
                    time_plot = np.asarray(
                        [float(row["start_time_zero_s"]) for row in data]
                    )

                    ############    WINDOW_SIZE    #################
                    # Determine the window size based on the SET_MIN_RTT setting
                    if SET_MIN_RTT == "constant_min_rtt":
                        WINDOW_SIZE = PERIOD_CONSTANT

                    elif SET_MIN_RTT == "custom_min_rtt":
                        WINDOW_SIZE = np.min(rtt_s) * WS_TIME

                    elif SET_MIN_RTT == "initial_rtt":
                        WINDOW_SIZE = rtt_s[0] * WS_TIME

                    elif SET_MIN_RTT == "custom_min_rtt_slow_start":
                        # Find the first index where a packet loss occurred
                        loss_index = next(
                            (
                                index
                                for index, item in enumerate(data)
                                if int(item["lost_pkt"]) > 0
                            ),
                            None,
                        )
                        if loss_index is not None:
                            filtered_df = pd.DataFrame(data[:loss_index])
                            min_rtt = filtered_df["rtt_s"].min()
                            WINDOW_SIZE = min_rtt * WS_TIME

                    ############    PACKET LOSS TIME    #################
                    # Find the time of first packet drop from log file
                    # x_dp = functions_SEARCH.find_first_nonzero_value(data, 'lost_pkt', 'start_time_zero_s')
                    # x_dp = functions_SEARCH.find_drop_in_slow_start(data, 'ssthresh_pkt', 'ss_status', 'start_time_zero_s')
                    x_dp = functions_SEARCH.find_drop_in_slow_start_new(
                        data, "ssthresh_pkt", "ss_status", "start_time_zero_s", "lost_pkt"
                    )

                    # Find the time of packet loss from pcap file
                    x_dp_pcap = functions_SEARCH.find_pkt_loss_pcap(
                        f"{PCAP_FOLDER_NAME}/tcp_run_{case}.csv", satellite_type
                    )

                    ############    ECN flag    #################
                    # Find the first time that Congestion Experienced (CE flag) is reported
                    x_ce_ecn_flag = functions_SEARCH.find_x_ce_ecn(
                        f"{PCAP_FOLDER_NAME}/tcp_run_{case}.csv"
                    )

                    ############    PLOT_LIMITATION    #################
                    # Limit the plot based on the satellite type
                    if satellite_type == "viasat":

                        # limit o axis on figures for viasat
                        limit_axis_fig = [
                            [-0.1, 60],
                            [-0.1, 200],
                            [-0.1, 350],
                            [-0.1, 9000],
                            None,
                            None,
                            [-0.1, 160],
                            [-1.5, 1.5],
                        ]

                    elif satellite_type == "starlink":

                        # limit o axis on figures for starlink
                        limit_axis_fig = [
                            [-0.1, 60],
                            [-0.1, 200],
                            [-0.1, 350],
                            [-0.1, 300],
                            [-5, 400],
                            [-0.01, x_dp + 0.75],
                            [-0.1, 8],
                            [-1.5, 1.5],
                        ]

                    elif satellite_type == "lte":

                        # limit o axis on figures for starlink
                        limit_axis_fig = [
                            [-0.1, 5],
                            [-0.1, 80],
                            [-0.1, 100],
                            [-0.1, 800],
                            [-5, 800],
                            [-0.01, x_dp + 0.75],
                            [-0.1, 8],
                            [-1.5, 1.5],
                        ]

                    ############    ONE_WAY_LATENCY    #################
                    # FIRST_DESIRED_LATENCY = rtt[0]*2
                    # SECOND_DESIRED_LATENCY = rtt[0]/2
                    # Find the fl latency to find the x_cg based on first and second desired latency time
                    fl_latency_offset, fl_time, x_cg_one_way_delay = (
                        functions_SEARCH.one_way_delay_changes(
                            SERVER_IP,
                            f"{PCAP_FOLDER_NAME}/tcp_run_{case}.csv",
                            None,
                            limit_axis_fig[4],
                            limit_axis_fig[5],
                            x_dp,
                            FIRST_DESIRED_LATENCY,
                            SECOND_DESIRED_LATENCY,
                        )
                    )

                    ############    Throughput    #################
                    # Calculate throughput for desired INTERVAL and for specific data filtered by SERVER_IP
                    throughput, throughput_time, capacity = (
                        functions_SEARCH.calculate_throughput(
                            f"{PCAP_FOLDER_NAME}/tcp_run_{case}.csv",
                            SERVER_IP,
                            INTERVAL,
                            THROUGHPUT_WINDOW_SIZE,
                            THROUGHPUT_SLIDING_WINDOW,
                            None,
                        )
                    )

                    ############    SLOW_START_RATE    #################
                    # Find slow start rate and find the x_cg based on slow start rate
                    ss_rate, x_cg_ss_rate = functions_SEARCH.find_slow_start_rate(
                        cwnd, rtt_s, time_plot, capacity
                    )

                    ############    APPROXIMATION    #################
                    # Approximate delivered byte, shifted back , and find the norm
                    delv_window_at_shift, delv_window, time_norm, norm_approx = (
                        functions_SEARCH.approximation_search1_d(
                            data,
                            "each_delv_MB",
                            "start_time_zero_s",
                            "rtt_s",
                            WINDOW_SIZE,
                            BIN_N,
                            "interpld",
                        )
                    )
                    # Save norm_approx values in a csv file
                    file_path = os.path.join(result_folder, f"Output_files_{WS_TIME}")
                    if not os.path.exists(file_path):
                        os.makedirs(file_path)
                    csv_filename2 = os.path.join(file_path, f"norm_approx_{case}.csv")
                    functions_SEARCH.save_list_to_csv2(
                        time_norm,
                        norm_approx,
                        delv_window,
                        delv_window_at_shift,
                        csv_filename2,
                        "Time",
                        "Norm_approx",
                        "delv_window",
                        "delv_window_at_shift",
                    )

                    # #CHANGE
                    # # Parameters for analysis the num of extra bins to cover shift time and can do SEARCH
                    # EXTRA_BINS_VALUES = np.arange(1, 41)
                    # file_path = os.path.join(result_folder, f'Output_files_{WS_TIME}')
                    # if not os.path.exists(file_path):
                    #     os.makedirs(file_path)
                    # csv_filename2 = os.path.join(file_path, f'num_search_do{case}.csv')
                    # file_vars_1 = []
                    # for EXTRA_BINS in EXTRA_BINS_VALUES:
                    #     # Approximate delivered byte, shifted back , and find the norm
                    #     delv_window_at_shift, delv_window, time_norm, norm_approx, number_do_search, number_end_bin_boundaries, \
                    #         rtt_in_bin_boundary = functions_SEARCH.approximation_search1_d_find_bins(data, 'each_delv_MB',
                    #                                                                                  'start_time_zero_s',
                    #                                                                                  'rtt_s',
                    #                                                                                  WINDOW_SIZE,
                    #                                                                                  BIN_N,
                    #                                                                                  EXTRA_BINS,
                    #                                                                                  "interpld")
                    #
                    #
                    #     x_ex_approx_list, x_ex_approx = functions_SEARCH.find_exit_point(norm_approx, time_norm, THRESH,
                    #                                                                      None)
                    #     # RESEARCH with approximation is success or not (success = 1: success   success = 0: fail)
                    #     success_approx = functions_SEARCH.find_success(x_cg_one_way_delay, x_dp, x_ex_approx)
                    #
                    #     if x_dp is not None and x_ex_approx is not None:
                    #         hr_approx = x_dp - x_ex_approx
                    #
                    #     if success_approx == 0:
                    #         if hr_approx < 0:
                    #             late_exit = 1
                    #             early_exit = 0
                    #         else:
                    #             late_exit = 0
                    #             early_exit = 1
                    #     else:
                    #         late_exit = 0
                    #         early_exit = 0
                    #     variable_header_1 = ['x_ex','x_cg','x_dp','num_extra_bins', 'number_end_bin_bound',
                    #                          'number_do_search', 'rtt_in_bin_bound', 'initial_rtt', 'timing', 'late', 'early']
                    #     # Variables append to a list
                    #     file_vars_1.append((x_ex_approx, x_cg_one_way_delay, x_dp, EXTRA_BINS, number_end_bin_boundaries, number_do_search, rtt_in_bin_boundary, rtt_s[0], success_approx, late_exit, early_exit))
                    #
                    #     # Write the data to a CSV file
                    #     functions_SEARCH.write_data_to_csv_float(csv_filename2, file_vars_1, variable_header_1)
                    #

                    # Find exit slow start time by approximated norm >= THRESH
                    x_ex_approx_list, x_ex_approx = functions_SEARCH.find_exit_point(
                        norm_approx, time_norm, THRESH, None
                    )

                    # ###########    RATES    #################
                    # Find the cwnd and rtt at the exit point(x_ex) rtt_ex,
                    rtt_ex, cwnd_ex = functions_SEARCH.find_value_in_ex(
                        data, "start_time_zero_s", "rtt_s", "cwnd_MB", x_ex_approx
                    )

                    # RESEARCH with approximation is success or not (success = 1: success   success = 0: fail)
                    success_approx = functions_SEARCH.find_success(
                        x_cg_one_way_delay, x_dp, x_ex_approx
                    )

                    if x_dp is not None and x_ex_approx is not None:
                        hr_approx = x_dp - x_ex_approx
                    ######################### Plot ##################################
                    make_plot = 1

                    if make_plot == 1:
                        # Plot norm approximation
                        functions_SEARCH.plot_one_line(
                            norm_approx,
                            time_norm,
                            x_dp,
                            x_ex_approx,
                            x_cg_one_way_delay,
                            None,
                            "Normalized",
                            "Time (s)",
                            "Approximation_norm_SEARCH1.0d",
                            limit_axis_fig[7],
                            folder_name,
                            f"approx{case}.png",
                            "zero_line",
                        )

                        # Plot twice delivered byte inn shift and current delivered byte for approximation
                        twice_delv_window_at_shift = 2 * np.asarray(delv_window_at_shift)
                        functions_SEARCH.plot_two_line(
                            time_norm,
                            twice_delv_window_at_shift,
                            time_norm,
                            delv_window,
                            x_dp,
                            "Twice_delv_byte_in_shift",
                            "Cur_delv_byte",
                            "Volume (Mb)",
                            "Time (s)",
                            "Approximation_SEARCH1.0d",
                            limit_axis_fig[6],
                            folder_name,
                            f"approx_byte{case}.png",
                        )

                        # Plot throughput, slow start rate, rtt,  fl latency, approximated sent and delivered byte, approximated norm
                        functions_SEARCH.plot_six_graphs(
                            throughput,
                            throughput_time,
                            ss_rate,
                            time_plot,
                            rtt,
                            time_plot,
                            fl_latency_offset,
                            fl_time,
                            twice_delv_window_at_shift,
                            time_norm,
                            delv_window,
                            time_norm,
                            norm_approx,
                            time_norm,
                            "max_throughput",
                            "twice_delv_byte_in_shift",
                            "cur_delv_byte",
                            None,
                            x_dp,
                            x_ex_approx,
                            x_cg_one_way_delay,
                            None,
                            "time (s)",
                            "throughput (Mbps)",
                            "cwnd/rtt (Mbps)",
                            "RTT (ms)",
                            "FL Latency Offset",
                            "volume (Mb)",
                            "2*delv_in_shift - cur_delv (normalized)",
                            "throughput over time",
                            "slow start rate",
                            "RTT",
                            "FL Latency Offset vs Time",
                            "windows volumes_SEARCH1.0d",
                            "norm_SEARCH1.0d",
                            limit_axis_fig,
                            folder_name,
                            f"all{case}.png",
                        )

                    ############################# CSV file ###########################################
                    # Save x_ex, x_dp, ... in csv file
                    csv = 1

                    if csv == 1:
                        # Set the csv file path
                        csv_file_path = os.path.join(result_folder, VARIABLE_FILE)
                        # Header of variable file
                        variable_header = [
                            "run",
                            "x_cg",
                            "x_dp",
                            "x_ex_approx",
                            "success_approx",
                            "x_dp_pcap",
                            "x_ce",
                            "rtt_ex",
                        ]
                        # Variables append to a list
                        file_vars.append(
                            (
                                case,
                                x_cg_one_way_delay,
                                x_dp,
                                x_ex_approx,
                                success_approx,
                                x_dp_pcap,
                                x_ce_ecn_flag,
                                rtt_ex,
                            )
                        )

                        # Write the data to a CSV file
                        functions_SEARCH.write_data_to_csv_float(
                            csv_file_path, file_vars, variable_header
                        )

                        # Save the result data to a result.csv file for sensitivity analysis (Window size and threshold
                        # sensitivity)
                        result_header = ["x_dp", "x_cg_one_way_delay"]
                        result_data.append((x_dp, x_cg_one_way_delay))
                        destination_output_folder = os.path.join(
                            result_folder, f"Output_files_{WS_TIME}"
                        )
                        result_csv_file_path = os.path.join(
                            destination_output_folder, "result.csv"
                        )
                        functions_SEARCH.write_data_to_csv_float(
                            result_csv_file_path, result_data, result_header
                        )

                    ############################# KERNEL Analysis ###########################################
                    KERNEL = 1

                    if KERNEL == 1:
                        folder_name_kernel = f"S1d_network_{satellite_type}"
                        result_folder_kernel = os.path.join(
                            cwd, result_folder, folder_name_kernel
                        )
                        os.makedirs(result_folder_kernel, exist_ok=True)

                        exit_search = np.asarray(
                            [
                                float(row["search_ex_time_s"])
                                for row in data
                                if row["search_ex_time_s"]
                            ]
                        )

                        now_time_ms_from_zero = np.asarray(
                            [
                                float(row["search_time_s"])
                                for row in data
                                if row["search_time_s"]
                            ]
                        )
                        current_wind_MB = np.asarray(
                            [
                                float(row["current_wind_MB"])
                                for row in data
                                if row["current_wind_MB"]
                            ]
                        )
                        prev_wind_MB = np.asarray(
                            [
                                float(row["prev_wind_MB"])
                                for row in data
                                if row["prev_wind_MB"]
                            ]
                        )
                        norm = np.asarray(
                            [float(row["norm"]) for row in data if row["norm"]]
                        )

                        functions_SEARCH.plot_data_kernel(
                            now_time_ms_from_zero,
                            current_wind_MB,
                            prev_wind_MB,
                            norm,
                            exit_search[0],
                            x_dp,
                            case,
                            result_folder_kernel,
                        )

                        functions_SEARCH.plot_all_with_kernel(
                            throughput,
                            throughput_time,
                            twice_delv_window_at_shift,
                            time_norm,
                            delv_window,
                            norm_approx,
                            fl_latency_offset,
                            fl_time,
                            now_time_ms_from_zero,
                            current_wind_MB,
                            prev_wind_MB,
                            norm,
                            exit_search[0],
                            x_dp,
                            x_ex_approx,
                            x_cg_one_way_delay,
                            limit_axis_fig,
                            result_folder_kernel,
                            f"all_kernel{case}.png",
                        )

                destination_copy_folder = os.path.join(cwd, "sens_bin")
                if not os.path.exists(destination_copy_folder):
                    # If it doesn't exist, create it
                    os.makedirs(destination_copy_folder, exist_ok=True)
                destination_variable_file = os.path.join(
                    destination_copy_folder, VARIABLE_FILE
                )
                shutil.copy(csv_file_path, destination_variable_file)
