"""Python version
'3.8.17 (default, Jul  5 2023, 20:44:21) [MSC v.1916 64 bit (AMD64)]'
Version info.
sys.version_info(major=3, minor=8, micro=17, releaselevel='final', serial=0)
"""
import csv
import numpy as np
from scipy.interpolate import interp1d
import pandas as pd
import matplotlib.pyplot as plt
import os
from itertools import zip_longest
from collections import deque


################################-------------------------------------------------###################################
# Function to read data from a CSV file, taking in the file address as
# a parameter
def read_csv_data(address):
    """
    This function takes in a file address as a parameter and reads data from a CSV file. The function opens the CSV file
    and creates a DictReader object to read the data. It then loops through the rows of the CSV file, appending each row
    to a list. Finally, the function returns the list of data.

    Parameters:
        address (str): A string representing the file address of the CSV file.

    Returns:
        list: A list of dictionaries, where each dictionary represents a row of data from the CSV file.
    """
    # Open the CSV file and create a DictReader object
    with open(address, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        data = []
        # Loop through the rows of the CSV file and append each one to the data list
        for row in reader:
            data.append(row)
    # Return the data list
    return data


################################-------------------------------------------------###################################
# Function to find the value of a column when at the first time it is not zero
def find_first_nonzero_value(data, given_column, related_column):
    """
    Given a CSV data file and two column names, returns the value in the related column that corresponds to the first
    non-zero value in the given column. If the given column is zero for all rows, returns None.

    Parameters:
        data (list of dicts): The CSV data as a list of dictionaries, where each dictionary represents a row.
        given_column (str): The name of the column to search for non-zero values.
        related_column (str): The name of the column to get the related value from.

    Returns:
        The value in the related column that corresponds to the first non-zero value in the given column, or None if
        the given column is zero for all rows.
    """
    # Extract the data from the given and related columns as lists of floats
    given_data = [float(row[given_column]) for row in data]
    related_data = [float(row[related_column]) for row in data]

    # Loop through the data in the given column
    for i in range(len(given_data)):
        # If the value in the given column is not zero, return the corresponding value from the related column
        if given_data[i] != 0:
            return related_data[i]

    # If we haven't returned a value by now, that means the given column is zero for all rows, so return None
    return None


################################-------------------------------------------------###################################
# Function to last time drop in slow-start
def find_drop_in_slow_start(data, ssthresh, cc_state, time):
    df = pd.DataFrame(data)
    df_tmp = df.loc[(df[ssthresh] == '2147483647') & (df[cc_state].shift(-1) != '1')]

    if df_tmp.shape[0] > 1:
        print(df_tmp)

    if df_tmp.empty:
        time = df.tail(1)[time].astype(float).values[0]
    else:
        time = df_tmp.tail(1)[time].astype(float).values[0]
    return time


################################-------------------------------------------------###################################
# Function to last time drop in slow-start
def find_drop_in_slow_start_new(data, ssthresh, ss_status, time, lost):
    df = pd.DataFrame(data)

    # Define default values
    default_values = {'ssthresh': '2147483647', 'ss_status': '1', 'lost': '0'}

    # Create masks for when the values in the specified columns are equal to the default values
    mask_change1 = ((df[lost] == default_values['lost'])).astype(int)
    mask_change2 = ((df[ssthresh] == default_values['ssthresh'])).astype(int)
    # mask_change3 = ((df[ss_status] == default_values['ss_status'])).astype(int)

    # Find the indices where the conditions change from True to False
    change_indices1 = np.asarray(np.where(mask_change1.diff() == 1)).flatten()
    change_indices2 = np.asarray(np.where(mask_change2.diff() == 1)).flatten()
    # change_indices3 = np.asarray(np.where(mask_change3.diff() == 1)).flatten()

    # find the last same index in all three masks
    change_indices = np.intersect1d(change_indices1, change_indices2)
    # change_indices = np.intersect1d(change_indices, change_indices3)
    if len(change_indices) == 0:
        change_index = 0
    else:
        change_index = change_indices[-1]

    if len(change_indices) > 1:
        print(change_indices)
    # Find the first index after change_index that lost is not zero
    df_tmp = df.loc[change_index:]
    df_tmp = df_tmp.loc[df_tmp[lost] != '0']
    if df_tmp.empty:
        time = df.tail(1)[time].astype(float).values[0]
    else:
        time = df_tmp.head(1)[time].astype(float).values[0]

    return time


################################-------------------------------------------------###################################
# Function to find the first occurrence of packet loss
def find_pkt_loss_pcap(file, sattelite_type):
    """
    Finds the time value corresponding to the first occurrence of packet loss in a network traffic PCAP file.

    Parameters:
        file (str): Path to the PCAP file containing network traffic data.
        sattelite_type (str):bType of satellite that can be 'viasat' or 'starlink'    

    Returns:
        time (float): Time value corresponding to the first occurrence of packet loss.
    """

    # Read the CSV file into a DataFrame
    try:
        # Read the CSV file using the Python-based parsing engine
        df = pd.read_csv(file, engine='python')
    except pd.errors.ParserError as e:
        print(f"ParserError: {e}")

    # Find the first row where the ack number is greater than 1000 (sync the time of pcap file and log file)
    first_row = df[df['Ack number'] > 1000].iloc[0]

    # Get the time value from the first row
    time_first_ack = first_row['Time']

    df['Time'] = df['Time'] - time_first_ack

    if sattelite_type == 'viasat':
        # Find the index of the first row where 'duplicate_ack' is 3
        df_tmp = df.loc[df['duplicate_ack'] == 3]
    else:
        # Find the index of the first row where 'duplicate_ack' is 3 or 'SACK' is 1
        df_tmp = df.loc[(df['duplicate_ack'] == 3) | (df['SACK'] == 1)]

    # Find the index if drop happned. Otherwise give the last index
    if df_tmp.empty:
        index = df.tail(1).index[0]
    else:
        index = df_tmp.index[0]

    # Get the corresponding time value
    time = df.loc[index, 'Time']

    return time


################################-------------------------------------------------###################################
# Function to find the Congestion Experienced(CE) in a network traffic
def find_x_ce_ecn(file):
    """
    Finds the time value corresponding to the first occurrence of 'Congestion Experienced' in a network traffic CSV file.

    Parameters:
        file (str): Path to the CSV file containing network traffic data.

    Returns:
        time (float): Time value corresponding to the first occurrence of 'Congestion Experienced'.
    """

    # Read the CSV file into a DataFrame
    df = pd.read_csv(file)

    # Find the first row where the ack number is greater than 1000 (sync the time of pcap file and log file)
    first_row = df[df['Ack number'] > 1000].iloc[0]

    # Get the time value from the first row
    time_first_ack = first_row['Time']
    df['Time'] = df['Time'] - time_first_ack

    if 'CE' in df.columns:
        ce_indices = df[(df['CE'] == 'Congestion Experienced') | (df['CE'] == 3)].index
        if len(ce_indices) > 0:
            index = ce_indices[0]
            time = df.loc[index, 'Time']
        else:
            time = None
    else:
        time = None

    return time


################################-------------------------------------------------###################################
# Function to calculate the normalized difference between two lists of values
def find_norm(SENT, DEL, x_out):
    """
    Calculates the normalized difference between SENT and DEL lists.

    Parameters:
    SENT: A list of integers representing the bytes sent.
    DEL: A list of integers representing the bytes delivered.
    x_out: A number of DEl that does not have corresponding SENT point

    Returns:
        norm: A list of floats representing the normalized difference between SENT and DEL.
    """
    norm = []
    # Remove x_out number of elements from the beginning of the DEL list
    DEL = DEL[x_out:]

    for i in range(len(DEL)):
        # Calculate the difference between SENT and DEL at index i
        dis_ = SENT[i] - DEL[i]
        if SENT[i] != 0:
            # Calculate the normalized difference by dividing the difference by SENT at index i
            norm_ = dis_ / SENT[i]
            norm.append(norm_)
    return norm


################################-------------------------------------------------###################################
# Function to find the exit point based on a normalized signal, time stamp, threshold value,
# and optional x-limit value
def find_exit_point(norm, time_stamp, thresh, x_limit):
    """
    Finds the exit point based on the normalized difference between two sets of data.

    Parameters:
        norm (list): A list of normalized differences between two sets of data.
        time_stamp (list): A list of time stamps corresponding to the data points in `norm`.
        thresh (float): The threshold value used to determine the exit point.
        x_limit (float, optional): The maximum value of the x-axis for the data. If not provided, the default value is 70.

    Returns:
        tuple: A tuple containing two items:
            - list or None: A list of all possible exit points found.
            - float or None: The first exit point found, or `None` if no exit points were found.
    """
    # List to store exit points found
    x_ex_list = []
    for i in range(len(norm)):
        # Find the exit point before packet drop (if we do not have packet drop, we set the limit big enough to find the exit point)
        if x_limit is not None:
            x_limit_ = x_limit
        else:
            x_limit_ = 70
        # Check if the time stamp is within the x-limit
        if time_stamp[i] <= x_limit_:
            # Check if the normalized value is above the threshold
            if norm[i] >= thresh:
                # Check if first data or the previous normalized value is below the threshold
                if i == 0 or norm[i - 1] < thresh:
                    # Save the exit point
                    x_exit = time_stamp[i]  # second
                    x_ex_list.append(x_exit)

    # If exit points were found, return the minimum exit point, else return None
    if len(x_ex_list) != 0:
        x_ex = np.min(x_ex_list)
        return x_ex_list, x_ex
    else:
        return None, None


################################-------------------------------------------------###################################
# Function to find the number of files in a folder
def count_files_in_folder(ADDRESS):
    """
    open a folder and find the number of files in it

    parameters:
        ADDRESS: string representing the folder path

    Returns:
        Integer value representing the number of files in a folder
    """
    # Open folder position
    files = os.listdir(ADDRESS)
    # Find the number of files in the folder
    num_files = len(files)
    return num_files


################################-------------------------------------------------###################################
# Function to open a file
def open_file(ADDRESS):
    """
    Open a file and read its lines.

    Parameters:
        ADDRESS: string representing the file path.

    Returns:
        List of strings, each string representing a line of the file.
    """
    # Open file position to read
    file = open(ADDRESS, 'r')
    # Read lines of file
    lines = file.read().splitlines()
    file.close()
    return lines


################################-------------------------------------------------###################################
def save_list_to_csv(time_list, data_list, filename, header1, header2):
    """
        Saves the values of a list to a CSV file.

        Parameters:
        data_list: A list of floats.
        time_list:  A list of floats.
        filename: The name of the CSV file to save.
        header1, header2: The column header in CSV file

        Returns:
        None
        """
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([header1, header2])  # Write the header row
        # for value in list:
        #     writer.writerow([value])
        for i in range(len(data_list)):
            writer.writerow([time_list[i], data_list[i]])


################################-------------------------------------------------###################################
def one_way_delay_changes(server_ip, file_path, fig_name, ylim, xlim, x_dp, first_desired_value, second_desired_value):
    """
     Analyzes one-way latency changes and detects specific points in the latency offset over time.

     Parameters:
         server_ip (str): The IP address of the server.
         file_path (str): Path to the CSV file containing network traffic data.
         fig_name (str): Path to the output figure file.
         ylim (tuple or None): Y-axis limits for the latency plot.
         xlim (tuple or None): X-axis limits for the latency plot.
         x_dp (float or None): Time of packet loss (x-axis vertical line).
         first_desired_value (float): Threshold value for the first desired latency offset.
         second_desired_value (float): Threshold value for the second desired latency offset.

     Returns:
         fl_latency_offset (list): List of latency offset values in the forward direction.
         fl_time (list): List of corresponding time values for latency offset.
         time_x_cg (float or None): Detected time at the capacity threshold, or None.
    """

    # Initialize lists to store latency offset values and corresponding time values
    rl_latency_offset = []
    fl_latency_offset = []
    rl_time = []
    fl_time = []
    srv_min_timestamp = None
    clt_min_timestamp = None
    init_rtt = None

    # Read network traffic data from the CSV file into a DataFrame
    df = pd.read_csv(file_path)

    # Initialize the variables
    rl_latency_offset_ = None
    fl_latency_offset_ = None
    time_rl = None
    time_fl = None

    # Find the first row where the ack number is greater than 1000 (sync the time of pcap file and log file)
    first_row = df[df['Ack number'] > 1000].iloc[0]

    # Get the time value from the first row
    time_first_ack = first_row['Time']

    # df['Time'] = df['Time'] - df['Time'].iloc[0]
    df['Time'] = df['Time'] - time_first_ack

    # Iterate through DataFrame rows to analyze latency offsets
    for row in df.itertuples(index=False):
        # Detect minimum timestamps for server and client
        if not srv_min_timestamp and row.Source == server_ip:
            srv_min_timestamp = row.TSval

        if not clt_min_timestamp and row.Destination == server_ip:
            clt_min_timestamp = row.TSval

        # Calculate latency offsets and time values
        if clt_min_timestamp and srv_min_timestamp:
            if row.Source == server_ip:  # Forward packet, measure RL latency
                rl_latency_offset_ = row.TSval - row.TSecr - srv_min_timestamp + clt_min_timestamp
                time_rl = row.Time
            else:
                # Return Link Packet, measure FL latency
                if not init_rtt:
                    init_rtt = row.TSval - row.TSecr + srv_min_timestamp - clt_min_timestamp
                fl_latency_offset_ = row.TSval - row.TSecr + srv_min_timestamp - clt_min_timestamp - init_rtt
                time_fl = row.Time

        # Append latency offset and time values to corresponding lists
        rl_latency_offset.append(rl_latency_offset_)
        fl_latency_offset.append(fl_latency_offset_)
        rl_time.append(time_rl)
        fl_time.append(time_fl)

    # Filter out None values from fl_latency_offset
    fl_latency_offset_ = [latency for latency in fl_latency_offset if latency is not None]
    fl_latency_offset_ = np.asarray(fl_latency_offset_)
    fl_latency_offset_ = fl_latency_offset_[~np.isnan(fl_latency_offset_)]

    # Use 110% of 1-percential value as second desired value if given value is lower than that
    thresh = np.percentile(fl_latency_offset_, 1) * 1.1
    if second_desired_value < thresh:
        second_desired_value = thresh
        first_desired_value = thresh * 4
        print("Adjusting Congestion Detection Threshold: ", first_desired_value, second_desired_value)

    # Make array of values greater than first_desired_value
    ind_ = np.asarray(np.where(fl_latency_offset_ >= first_desired_value))

    # Check if there are any timestamps greater than the first desired value
    if np.any(ind_):
        # Get the index of the timestamp
        ind_next = ind_[0, 0]
        ind_curr = ind_next - 1
        # Iterate backwards from the timestamp index
        while ind_curr >= 0:
            # Check if the value is about second desired value
            if fl_latency_offset_[ind_curr] <= second_desired_value:
                time_x_cg = fl_time[ind_curr]
                break
            ind_curr -= 1
    else:
        time_x_cg = None

    if fig_name is not None:
        plt.figure()
        plt.plot(fl_time, fl_latency_offset)
        if x_dp is not None:
            plt.axvline(x_dp, linewidth=4, color='r', linestyle='--', label=f'Packet loss = {x_dp: .2f}')
        if time_x_cg is not None:
            plt.axvline(time_x_cg, linewidth=4, color='b', linestyle='--', label=f'At capacity = {time_x_cg: .2f}')
        plt.xticks(fontsize=17)
        plt.yticks(fontsize=17)
        if ylim is not None:
            plt.ylim(ylim)
        if xlim is not None:
            plt.xlim(xlim)
        plt.xlabel('Time (s)', fontsize=15)
        plt.ylabel('FL Latency Offset', fontsize=15)
        plt.title('FL Latency Offset vs Time', fontsize=15)
        plt.legend()
        plt.savefig(fig_name, bbox_inches='tight')
        plt.close()

    return fl_latency_offset, fl_time, time_x_cg


################################-------------------------------------------------###################################
def calculate_throughput(FILE_NAME_THROUGHPUT, ip_address, Interval, window_size, sliding_window, address_fig):
    """
    Calculates throughput values from wireshark data.

    Parameters:
        FILE_NAME_THROUGHPUT (str): The name of the CSV file containing network traffic data.
        ip_address (str): The IP address used for filtering packets in the DataFrame.
        Interval (float): The time interval (in seconds) used to calculate throughput.
        window_size (float): The size of the sliding window (in seconds) for calculating sliding throughput.
        sliding_window (float): The time step (in seconds) used to slide the window for sliding throughput.
        address_fig (str): The path to the output figure file.

    Returns:
        throughputs (list): A list of calculated throughput values (in Mbps) for each time interval.
        timestamps (list): A list of corresponding timestamps for the calculated throughput values.
        max_throughput (float or None): The maximum throughput value (in Mbps) within the sliding windows,
            or None if sliding window parameters are not provided.
     """

    cwd = os.getcwd()

    csv_file = os.path.join(cwd, FILE_NAME_THROUGHPUT)

    # Read the CSV file into a DataFrame
    df = pd.read_csv(csv_file)

    # Find the first row where the ack number is greater than 1000 (sync the time of pcap file and log file)
    first_row = df[df['Ack number'] > 1000].iloc[0]

    # Get the time value from the first row
    time_first_ack = first_row['Time']

    df['Time'] = df['Time'] - time_first_ack

    # Filter the DataFrame for packets with DSCP value = AF21
    df_af21 = df[df['Source'] == ip_address]

    # Initialize lists to store calculated throughput values and timestamps
    throughputs = []
    timestamps = []

    # Initialize the start and end times for the throughput calculation window
    start_time = df_af21['Time'].iloc[0]
    end_time = start_time + Interval

    # Iterate through time intervals and calculate throughput
    while end_time <= df_af21['Time'].iloc[-1]:
        # Filter data for the current time window
        window_data = df_af21.loc[(df_af21['Time'] >= start_time) & (df_af21['Time'] < end_time)]
        # Calculate total bytes and throughput for the current window
        if not window_data.empty:
            total_bytes = window_data['Length'].sum() * 8 * 1e-6  # Convert length from bytes to Megabits
            window_duration = end_time - start_time
            throughput = total_bytes / window_duration
            throughputs.append(throughput)
            timestamps.append(end_time)

            # Update start and end times based on current window
            if window_data['Time'].iloc[-1] == start_time:
                start_time = end_time
            else:
                start_time = window_data['Time'].iloc[-1]
            end_time = start_time + Interval
        else:
            # If no data in window, move the window
            start_time = end_time
            end_time = start_time + Interval

    # Check if both window_size and sliding_window are provided
    if window_size and sliding_window is not None:

        # Initialize lists to store sliding throughput values and corresponding timestamps
        throughputs_sliding = []
        timestamps_sliding = []

        # Initialize sliding window start and end times
        start_time_sliding = df_af21['Time'].iloc[0]
        end_time_sliding = start_time_sliding + window_size

        # Iterate through sliding windows
        while end_time_sliding <= df_af21['Time'].iloc[-1]:
            # Filter data for the current sliding window
            window_data_sliding = df_af21.loc[
                (df_af21['Time'] >= start_time_sliding) & (df_af21['Time'] <= end_time_sliding)]
            # Calculate total bytes and sliding window throughput
            total_bytes_sliding = window_data_sliding[
                                      'Length'].sum() * 8 * 1e-6  # Convert length from bytes to Mega bits
            window_duration_sliding = end_time_sliding - start_time_sliding
            throughput_sliding = total_bytes_sliding / window_duration_sliding
            throughputs_sliding.append(throughput_sliding)
            timestamps_sliding.append(end_time_sliding)

            # Move sliding window forward
            start_time_sliding += sliding_window
            end_time_sliding += sliding_window
        # Find the maximum throughput
        max_throughput = max(throughputs_sliding)

        if address_fig is not None:
            plt.figure()
            # Plot the sliding window throughput
            plt.plot(timestamps_sliding, throughputs_sliding, linewidth=2, color='m')
            plt.axhline(max_throughput, linestyle='--', linewidth=3, color='blue')
            plt.xticks(fontsize=17)
            plt.yticks(fontsize=17)
            plt.xlabel('Time(s)', fontsize=15)
            plt.ylabel('Throughput (Mbps)', fontsize=15)
            plt.title('Throughput over Time', fontsize=15)
            plt.savefig(address_fig, bbox_inches='tight')
            plt.close()

    else:
        # If sliding window parameters are not provided set the max_throughput as None
        max_throughput = None

    # Return calculated throughput values, timestamps, and max_throughput (if applicable)
    return throughputs, timestamps, max_throughput


################################-------------------------------------------------###################################
# Function to computes the sending rate during slow start and identifies congestion exit time 
# if it surpasses the provided capacity
def find_slow_start_rate(cwnd, rtt_s, time_plot, capacity):
    """
        Calculates the sending rate during slow start phase and detects congestion exit time.

        Parameters:
            cwnd (float): Current congestion window size (in packets).
            rtt_s (float): Round-trip time in seconds.
            time_plot (array-like): Array containing time values corresponding to each congestion window size.
            capacity (float or None, optional): Link capacity in Mbps. If provided, the function checks for congestion exit.

        Returns:
            R (float): Calculated sending rate during slow start phase in Mbps.
            x_cg_new (float or None): Detected time of congestion exit (if capacity is provided), or None.
    """
    # Calculate sending rate R (Mbps)
    R = (cwnd / rtt_s) * 8  # Mb/s
    if capacity is not None:
        # Check if sending rate exceeds capacity
        ind_ = np.asarray(np.where(R > capacity))
        if np.any(ind_):
            ind_curr = ind_[0, 0]
            x_cg_new = time_plot[ind_curr]
    else:
        x_cg_new = None

    return R, x_cg_new


################################-------------------------------------------------###################################
# Function to find the value of 2 columns in the exit point time
def find_value_in_ex(data, column1, column2, column3, x_ex):
    """
    This function finds the values of `column2` and `column3` in `data`
    at the time specified by `x_ex` in `column1`.

    Parameters:
        data: a list of dictionaries representing rows of data.
        column1: aThe column name for the time information in the data.
        column2: The column name for the RTT information in the data.
        column3: The column name for the cwnd information in the data.
        x_ex: a float representing the time value at which to find the RTT and cwnd values.

    Returns:
        rtt_ex: a float representing the RTT value at the time specified by `x_ex`.
        cwnd_ex: a float representing the cwnd value at the time specified by `x_ex`.
    """
    # Extract the time, RTT, and cwnd values from the data and convert time to a numpy array
    time = [float(row[column1]) for row in data]
    rtt = [float(row[column2]) for row in data]
    cwnd = [float(row[column3]) for row in data]
    time = np.asarray(time)
    # Loop over each time value to find the values at the specified time
    for i_ in range(len(time)):
        # If `x_ex` is specified, find the index of the first time value that is greater than or equal to `x_ex`
        if x_ex is not None:
            ind_cap = np.asarray(np.where(time >= x_ex))
            if np.any(ind_cap):
                # If such an index exists, use the previous index to get the RTT and cwnd values
                ind_ = ind_cap[0, 0]
                ind_intersect = ind_ - 1
                rtt_ex = rtt[ind_intersect]
                cwnd_ex = cwnd[ind_intersect]
                break
        else:
            # If `x_ex` is None, return `None` for both values
            rtt_ex = None
            cwnd_ex = None

    return rtt_ex, cwnd_ex


################################-------------------------------------------------###################################
# Function to calculates the distance between the exit point and the
# first packet drop point, and checks if this distance is greater than
# the rtt at the exit point.
def find_headroom(rtt_ex, x_ex, x_dp):
    """
    This function calculates the headroom at the datapoint `x_dp` with
    respect to the exit point `x_ex` and the RTT value `rtt_ex`.

    Parameters:
        rtt_ex: a float representing the RTT value at the exit point.
        x_ex: a float representing the time value at the exit point.
        x_dp: a float representing the time value at the datapoint.

    Returns:
        HR: a float representing the headroom at the datapoint.
        space: a binary value (0 or 1) representing whether there is enough headroom at the datapoint.
    """

    # Check if both `x_ex` and `x_dp` are specified
    if x_ex is not None and x_dp is not None and rtt_ex is not None:
        # Calculate the headroom and check if it's greater than or equal to `rtt_ex`
        HR = x_dp - x_ex
        if HR >= rtt_ex:
            space = 1  # if we have HR>= RTT at exit point
        else:
            space = 0
    else:
        # If either `x_ex` or `x_dp` is not specified, set both values to `None`
        space = None
        HR = None

    return HR, space


################################-------------------------------------------------###################################
# Function to evaluates test success by verifying the exit point time lies between congestion and packet drop times;
# returns 1 (success), 0 (failure), or None (incomplete data)
def find_success(x_cg, x_dp, x_ex):
    """
    Determines if a test is successful or not based on the times of the congestion event, the
    first packet drop, and the exit point.

    Parameters:
        cg_time (float or None): Time of the congestion event.
        dp_time (float or None): Time of the first packet drop.
        ex_time (float or None): Time of the exit point.

    Returns:
        test (int or None): An integer representing the outcome of the test. 1 if successful, 0 if failed, and None if any of the arguments are None.
    """
    # Check that congestion event and first packet drop times are not None
    if x_cg is not None and x_dp is not None and x_ex is not None:
        # Determine if the exit point is between the congestion event and first packet drop times
        if x_cg <= x_ex <= x_dp:
            test = 1  # success
        else:
            test = 0  # failure
    else:
        # If either of the arguments is None, set test to None
        test = None

    return test


################################-------------------------------------------------###################################
# Function to write data(contain numpy objext) to a CSV file, taking
# in the filename to be created/overwritten, the data to be written,
# and the variable names to be included in the header row
def write_data_to_csv_float(filename, data, variable_name):
    """
    This function takes in a filename to be created/overwritten, a numpy array of data to be written, and a list of
    variable names to be included in the header row of the CSV file. The function opens the CSV file for writing and
    creates a CSV writer object. It then writes the variable names as the header row and loops through the data rows,
    converting any numpy objects to strings and writing each row to the CSV file.

    Parameters:
        filename (str): A string representing the name of the CSV file to be created/overwritten.
        data (numpy.ndarray): A numpy array of data to be written to the CSV file.
        variable_name (list): A list of strings representing the variable names to be included in the header row of the CSV file.

    Returns:
        None
    """
    # Open the CSV file for writing, with newline='' to prevent extra line breaks
    with open(filename, 'w', newline='') as csvfile:
        # Create a CSV writer object
        writer = csv.writer(csvfile)
        # Write the variable names as the header row
        writer.writerow(variable_name)
        # Loop through the data rows and write each one to the CSV file
        for row in data:
            # Convert any numpy objects to strings
            row = [str(x) if isinstance(x, np.generic) else x for x in row]
            # Write the row to the CSV file
            writer.writerow(row)


################################-------------------------------------------------###################################
# Function to extract data from a log file based on flow pointer
def find_data(LINE, FP):
    """
    Extracts relevant data from a list of log lines based on a given flow pointer.

    Parameters:
        LINE (List[str]): A list of log lines.
        FP (str): The flow pointer to match.

    Returns:
        A tuple of lists containing the following data: each_acked (float), now (float), ss_status (int),
        lost (int), sent_B (float), acked_B (float), cwnd (float), ssthresh (int), rtt (float).
    """
    each_acked = []
    now = []
    ss_status = []
    lost = []
    sent_B = []
    acked_B = []
    cwnd = []
    ssthresh = []
    rtt = []

    for line in LINE:
        # Check if the line matches the flow pointer
        if "flow pointer: " + FP + "]" in line:
            if "BW-INFO:" in line:
                if "Current-byte-acked " in line:
                    byte_acked = int(line.split("Current-byte-acked ")[1].split("]")[0]) * 1e-6  # MB
                    each_acked.append(byte_acked)

            if "ACK-INFO:" in line:

                if "kernel: [" in line and "]" in line:
                    try:
                        now_ = float(line.split("kernel: [")[1].split("]")[0])
                        now.append(now_)
                    except IndexError:
                        print("Error: Log line format is incorrect.")
                else:
                    print("Error: Log line does not contain the expected format.")

                if "SS-status " in line:
                    ss_status_ = int(line.split("SS-status ")[1].split("]")[0])
                    ss_status.append(ss_status_)

                if "Num-Lost " in line:
                    lost_ = int(line.split("Num-Lost ")[1].split("]")[0])  # packet
                    lost.append(lost_)

            if "Rate-INFO:" in line:

                if "Bytes-sent " in line:
                    b_sent = int(line.split("Bytes-sent ")[1].split("]")[0]) * 1e-6  # MB
                    sent_B.append(b_sent)

                if "Bytes-acked " in line:
                    b_acked = int(line.split("Bytes-acked ")[1].split("]")[0]) * 1e-6  # MB
                    acked_B.append(b_acked)

                if "cwnd " in line:
                    cwnd_ = int(line.split("cwnd ")[1].split("]")[0]) * 1448 * 1e-6  # MB
                    cwnd.append(cwnd_)

                if "SSthresh " in line:
                    ssthresh_ = int(line.split("SSthresh ")[1].split("]")[0])  # packet
                    ssthresh.append(ssthresh_)

                if "sample-RTT " in line:
                    s_rtt = int(line.split("sample-RTT ")[1].split("]")[0]) * 1e-3  # sec
                    rtt.append(s_rtt)

    return each_acked, now, ss_status, lost, sent_B, acked_B, cwnd, ssthresh, rtt


################################-------------------------------------------------###################################
# Function to write data to a CSV file, taking in the filename to be
# created/overwritten, the data to be written, and the variable names
# to be included in the header row
def write_data_to_csv(filename, data, variable_name):
    """
    This function takes in a filename to be created/overwritten, a list of data to be written, and a list of variable names
    to be included in the header row of the CSV file. The function opens the CSV file for writing and creates a CSV writer
    object. It then writes the variable names as the header row and loops through the data rows, writing each row to the
    CSV file.

    Parameters:
        filename (str): A string representing the name of the CSV file to be created/overwritten.
        data (list): A list of data to be written to the CSV file.
        variable_name (list): A list of strings representing the variable names to be included in the 
                              header row of the CSV file.

    Returns:
        None
    """
    # Open the CSV file for writing, with newline='' to prevent extra line breaks
    with open(filename, 'w', newline='') as csvfile:
        # Create a CSV writer object
        writer = csv.writer(csvfile)
        # Write the variable names as the header row
        writer.writerow(variable_name)
        # Loop through the data rows and write each one to the CSV file
        for row in data:
            # Write the row to the CSV file
            writer.writerow(row)


################################-------------------------------------------------###################################
# Function to set the start time to zero for a given list of timestamps
def adjust_timestamps_to_start_at_zero(data):
    """
    Given a list of timestamps, this function sets the start time to zero by subtracting the first timestamp from all the timestamps.

    Parameters:
        data: A list of timestamps.

    Returns:
        A list of adjusted timestamps, with the start time set to zero.
    """
    # Get the first timestamp in the data
    first_timestamp = data[0]
    # Subtract the first timestamp from each timestamp in the data to set the start time to zero
    now_ = [t - first_timestamp for t in data]
    # Return the adjusted timestamps
    return now_


################################-------------------------------------------------###################################
# Function to compute the value of each byte in a list of cumulative
# byte counts
def compute_each_byte(cum_byte):
    """
    This function takes in a list of cumulative byte counts and returns a list of computed byte values.

    Parameters:
        cum_byte: A list of cumulative byte counts.

    Returns:
        A list of computed byte values, where the value of each byte is calculated as the difference between the current cumulative byte
        count and the previous one. If the input list is empty, an empty list will be returned.
    """
    # Create an empty list to hold the computed values of each byte
    each_byte = []
    # Loop through the cumulative byte counts
    for i in range(len(cum_byte)):
        # If this is the first element, set the value of the first byte to the value of the cumulative byte count
        if i == 0:
            each_byte_ = cum_byte[0]
        # Otherwise, compute the value of the byte as the difference between the current cumulative byte count and the previous one
        else:
            each_byte_ = cum_byte[i] - cum_byte[i - 1]
        # Append the computed value to the each_byte list
        each_byte.append(each_byte_)
    # Return the list of computed byte values
    return each_byte


################################-------------------------------------------------###################################
# Function to plot a graph with optional markers and vertical lines
def plot_one_line(y_value, x_value, x_dp, x_ex, x_cg, x_cg_manual, y_label, x_label, title, ylim, path_folder,
                  file_name,
                  flag):
    """
    Plot a line graph with optional markers and vertical lines.

    Parameters:
        y_value (array): the data values to plot as the y-coordinates of the line.
        x_value (array): the x-coordinates of the data values.
        x_dp (float): the x-coordinate at which to draw a vertical line, indicating packet loss.
        x_ex (float): the x-coordinate at which to draw a vertical line, indicating exit time.
        x_cg (float): the x-coordinate at which to draw a vertical line, indicating the system at capacity.
        x_cg_manual (float): the x-coordinate at which to draw a verical line, indicating the system at capacity that manually set.
        y_label (str): the label for the y-axis.
        x_label (str): the label for the x-axis.
        title (str): the title of the plot.
        ylim (tuple): the lower and upper limits for the y-axis. If None, the limits are determined automatically.
        file_name (str): the file name to use for saving the plot. If empty, the plot is not saved.
        flag (str): if set to 'zero_line', a horizontal line is added at y=0.

    Returns:
        None

    Saves the plot to a file with the specified file name.
    """
    # Set the path for saving the figure
    cwd = os.getcwd()
    # Create a subdirectory called 'figure'
    data_dir = os.path.join(cwd, path_folder, 'figure')
    # Check if the directory exists
    if not os.path.exists(data_dir):
        # If it doesn't exist, create it
        os.makedirs(data_dir)
    # Join the directory path with the file name
    address_fig = os.path.join(data_dir, file_name)
    # Create a new figure with the specified size
    plt.figure(figsize=(8, 6))
    # Add a horizontal line at y=0 if the flag is set
    if flag == 'zero_line':
        plt.axhline(0, linewidth=2, color='m', linestyle='-')
    plt.plot(x_value, y_value, marker='o', markersize=5, color='dodgerblue', linestyle='-')
    # Add vertical lines at the specified x-coordinates with optional labels
    if x_dp is not None:
        plt.axvline(x_dp, linewidth=4, color='r', linestyle='--', label=f'Packet loss = {x_dp:.2f}')
    if x_cg is not None:
        plt.axvline(x_cg, linewidth=4, color='b', linestyle='--', label=f'At capacity = {x_cg: .2f}')
    if x_cg_manual is not None:
        plt.axvline(x_cg_manual, linewidth=4, color='lime')
    if x_ex is not None:
        plt.axvline(x_ex, linewidth=4, color='g', linestyle='--', label=f'exit time = {x_ex: .2f}')
    # Set the y-axis label and x-axis label
    plt.ylabel(y_label, fontsize=15)
    plt.xlabel(x_label, fontsize=15)
    # Set the y-axis limits if specified
    if ylim is not None:
        plt.ylim(ylim)
    # Set the x-axis limits if packet loss is specified
    if x_dp is not None:
        if x_ex is not None and x_ex >= x_dp:
            plt.xlim([-0.1, x_ex + 0.5])
        else:
            plt.xlim([-0.1, x_dp + 0.5])
    plt.xticks(fontsize=17)
    plt.yticks(fontsize=17)
    if title is not None:
        plt.title(title, fontsize=15)
    # plt.legend()
    # Save the figure to the specified file path and show it
    plt.savefig(address_fig, bbox_inches='tight')
    plt.close()


################################-------------------------------------------------###################################
# Function to plot 2 lines side by side on one figure
def plot_two_line(x_value1, y_value1, x_value2, y_value2, x_dp, label1, label2, ylabel, xlabel, title, ylim,
                  path_folder, file_name):
    """
    Plot two line graphs side by side, with optional vertical line.

    Parameters:
        x_value1 (array): the x-coordinates of the data values for the first line.
        y_value1 (array): the y-coordinates of the data values for the first line.
        x_value2 (array): the x-coordinates of the data values for the second line.
        y_value2 (array): the y-coordinates of the data values for the second line.
        x_dp (float): the x-coordinate at which to draw a vertical line. If less than or equal to 0, no line is drawn.
        label1 (str): the label for the first line.
        label2 (str): the label for the second line.
        ylabel (str): the label for the y-axis.
        xlabel (str): the label for the x-axis.
        title (str): the title of the plot.
        ylim (tuple): the lower and upper limits for the y-axis.
        file_name (str): the file name to use for saving the plot.

    Returns:
        None

    Saves the plot to a file with the specified file name.
    """
    # Path for saving figure
    cwd = os.getcwd()
    data_dir = os.path.join(cwd, path_folder, 'figure')
    if not os.path.exists(data_dir):
        os.makedirs(data_dir)
    # Join the directory path with the file name
    address_fig = os.path.join(data_dir, file_name)

    min_len = np.min([len(x_value1), len(y_value1)])
    x_value1 = x_value1[:min_len]
    y_value1 = y_value1[:min_len]
    # Create figure
    plt.figure(figsize=(8, 6))
    # Plot first line
    plt.plot(x_value1, y_value1, marker='o', markersize=5, color='b', linestyle='-', label=label1)
    # Plot second line
    plt.plot(x_value2, y_value2, marker='o', markersize=5, color='g', linestyle='-', label=label2)
    # Add vertical line if packet loss is specified
    if x_dp is not None:
        plt.axvline(x_dp, linewidth=4, color='r', linestyle='--', label=f'Packet loss')
    plt.ylabel(ylabel, fontsize=15)
    plt.xlabel(xlabel, fontsize=15)
    # Set the x-axis limits if packet loss is specified
    if x_dp is not None:
        plt.xlim([-0.1, x_dp + 0.5])
    plt.ylim(ylim)
    plt.xticks(fontsize=17)
    plt.yticks(fontsize=17)
    plt.title(title, fontsize=15)
    plt.legend()
    # Save the figure to the specified file path and show it
    plt.savefig(address_fig, bbox_inches='tight')
    plt.close()


################################-------------------------------------------------###################################
def plot_six_graphs(y_value1, x_value1, y_value2, x_value2, y_value3, x_value3, y_value4, x_value4, y_value5_1,
                    x_value5_1, y_value5_2, x_value5_2, y_value6, x_value6, label1, label2, label3, capacity, x_dp,
                    x_ex_approx, x_cg, x_dp_pcap,
                    x_label, y_label1, y_label2, y_label3, y_label4, y_label5, y_label6, title1, title2, title3, title4,
                    title5, title6,
                    limit_axis, path_folder, file_name):
    """
    Plot six graphs in one figure, arranged in 3 rows and 2 columns.

    Parameters:
        y_value1 (array) : the y-coordinate of the data values for the first graph.
        x_value1 (array) : the x-coordinates of the data values for the first graph.
        x_value2 (array) : the x-coordinate of the data value for the second graph.
        y_value2 (array) : the y-coordinate of the data value for the second graph.
        x_value3 (array) : the x-coordinate of the data value for third graph.
        y_value3 (array) : the y-coordinate of the data values for the third graph.
        y_value4 (array) : the x-coordinate of the data value for the forth graph.
        x_value4 (array) : the y-coordinate of the data values for the forth graph.
        y_value5_1 (array): the y-coordinates of the data values for the first line in the fifth graph.
        x_value5_1 (array): the x-coordinates of the data values for the first line in the fifth graph.
        y_value5_2 (array): the y-coordinates of the data values for the second line in the fifth graph.
        y_value5_2 (array): the y-coordinates of the data values for the second line in the fifth graph.
        y_value6 (array): the y_coordinates of the data values for the sixth graph.
        x_value6 (array): the x-coordinates of the data values for the sixth graph.
        x_dp (float): the x-coordinate at which to draw a vertical line in some graphs.
        x_ex_approx (float): the x-coordinate at which to draw a vertical line in some graphs.
        x_cg (float): the x-coordinate at which to draw a vertical line in some graphs.

    Returns:
        None

    Saves the plot to a file with the specified file name.
    """
    # Path for saving figure
    cwd = os.getcwd()
    data_dir = os.path.join(cwd, path_folder, 'figure')
    if not os.path.exists(data_dir):
        os.makedirs(data_dir)
    # Join the directory path with the file name
    address_fig = os.path.join(data_dir, file_name)

    # Create figure with 3 rows and 2 columns
    fig, axs = plt.subplots(2, 3, figsize=(25, 15))

    # Plot the first graph
    ax1 = axs[0, 0]
    ax1.plot(x_value1, y_value1, linewidth=2, color='m', linestyle='-')
    if capacity is not None:
        ax1.axhline(capacity, linestyle='--', linewidth=3, color='blue', label=label1)
    if limit_axis[1] is not None:
        ax1.set_ylim(limit_axis[1])
    if limit_axis[0] is not None:
        ax1.set_xlim(limit_axis[0])
    ax1.tick_params(axis='x', labelsize=17)
    ax1.tick_params(axis='y', labelsize=17)
    ax1.set_xlabel(x_label, fontsize=15)
    ax1.set_ylabel(y_label1, fontsize=15)
    ax1.set_title(title1, fontsize=15)
    # ax1.legend()

    # Plot the second graph
    ax2 = axs[0, 1]
    ax2.plot(x_value2, y_value2, marker='o', markersize=5, color='c', linestyle='-')
    if x_dp is not None:
        ax2.axvline(x_dp, linewidth=4, color='r', linestyle='--', label=f'Packet loss = {x_dp: .2f}')
    if x_cg is not None:
        ax2.axvline(x_cg, linewidth=4, color='b', linestyle='--', label=f'At capacity = {x_cg: .2f}')
    if x_dp is not None:
        ax2.set_xlim([-0.1, x_dp + 0.5])
    if limit_axis[2] is not None:
        ax2.set_ylim(limit_axis[2])
    ax2.tick_params(axis='x', labelsize=17)
    ax2.tick_params(axis='y', labelsize=17)
    ax2.set_xlabel(x_label, fontsize=15)
    ax2.set_ylabel(y_label2, fontsize=15)
    ax2.set_title(title2, fontsize=15)
    ax2.legend()

    # Plot the third graph
    ax3 = axs[0, 2]
    ax3.plot(x_value3, y_value3, marker='o', markersize=5, color='brown', linestyle='-')
    if x_dp is not None:
        ax3.axvline(x_dp, linewidth=4, color='r', linestyle='--', label=f'Packet loss = {x_dp: .2f}')
    if x_cg is not None:
        ax3.axvline(x_cg, linewidth=4, color='b', linestyle='--', label=f'At capacity = {x_cg: .2f}')
    if x_dp is not None:
        ax3.set_xlim([-0.1, x_dp + 0.5])
    if limit_axis[3] is not None:
        ax3.set_ylim(limit_axis[3])
    ax3.tick_params(axis='x', labelsize=17)
    ax3.tick_params(axis='y', labelsize=17)
    ax3.set_xlabel(x_label, fontsize=15)
    ax3.set_ylabel(y_label3, fontsize=15)
    ax3.set_title(title3, fontsize=15)
    ax3.legend()

    # Plot the forth graph
    ax4 = axs[1, 0]
    ax4.plot(x_value4, y_value4, color='darkcyan', linewidth=2)
    if x_dp is not None:
        ax4.axvline(x_dp, linewidth=4, color='r', linestyle='--', label=f'Packet loss = {x_dp: .2f}')
    if limit_axis[4] is not None:
        ax4.set_ylim(limit_axis[4])
    if limit_axis[5] is not None:
        ax4.set_xlim(limit_axis[5])
    if x_cg is not None:
        ax4.axvline(x_cg, linewidth=4, color='b', linestyle='--', label=f'At capacity = {x_cg: .2f}')
    ax4.tick_params(axis='x', labelsize=17)
    ax4.tick_params(axis='y', labelsize=17)
    ax4.set_xlabel(x_label, fontsize=15)
    ax4.set_ylabel(y_label4, fontsize=15)
    ax4.set_title(title4, fontsize=15)
    ax4.legend()

    # Plot the fifth graph
    ax5 = axs[1, 1]
    ax5.plot(x_value5_1, y_value5_1, marker='o', markersize=5, color='b', linestyle='-', label=label2)
    ax5.plot(x_value5_2, y_value5_2, marker='o', markersize=5, color='g', linestyle='-', label=label3)
    if x_dp is not None:
        ax5.axvline(x_dp, linewidth=4, color='r', linestyle='--', label='Packet loss')
    if x_dp is not None:
        ax5.set_xlim([-0.1, x_dp + 0.5])
    if limit_axis[6] is not None:
        ax5.set_ylim(limit_axis[6])
    ax5.tick_params(axis='x', labelsize=17)
    ax5.tick_params(axis='y', labelsize=17)
    ax5.set_xlabel(x_label, fontsize=15)
    ax5.set_ylabel(y_label5, fontsize=15)
    ax5.set_title(title5, fontsize=15)
    ax5.legend()

    # Plot the sixth graph
    ax6 = axs[1, 2]
    ax6.axhline(0, linewidth=2, color='m', linestyle='-')
    ax6.plot(x_value6, y_value6, marker='o', markersize=5, color='dodgerblue', linestyle='-')
    if x_dp is not None:
        ax6.axvline(x_dp, linewidth=4, color='r', linestyle='--', label=f'Packet loss = {x_dp: .2f}')
    if x_cg is not None:
        ax6.axvline(x_cg, linewidth=4, color='b', linestyle='--', label=f'At capacity = {x_cg: .2f}')
    if x_ex_approx is not None:
        ax6.axvline(x_ex_approx, linewidth=4, color='g', linestyle='--', label=f'Exit time = {x_ex_approx: .2f}')
    if x_dp is not None:
        if x_ex_approx is not None and x_ex_approx >= x_dp:
            ax6.set_xlim([-0.1, x_ex_approx + 0.5])
        else:
            ax6.set_xlim([-0.1, x_dp + 0.5])
    if limit_axis[7] is not None:
        ax6.set_ylim(limit_axis[7])
    ax6.tick_params(axis='x', labelsize=17)
    ax6.tick_params(axis='y', labelsize=17)
    ax6.set_xlabel(x_label, fontsize=15)
    ax6.set_ylabel(y_label6, fontsize=15)
    ax6.set_title(title6, fontsize=15)
    ax6.legend()

    # Adjust spacing and position of subplots
    fig.subplots_adjust(left=0.1, right=0.9, bottom=0.1, top=0.9, wspace=0.4, hspace=0.4)
    # Save the figure to the specified file path and show it
    plt.savefig(address_fig, bbox_inches='tight')
    plt.close()


################################-------------------------------------------------###################################
# Approximate delivered byte, shift back for curr RTT, estimate delivered byte at the shift time
def approximation_search1_d(data, column1, column2, column3, window_size, num_bins, interpolation_flag):
    """
    Parameters:
        data (list): A list of dictionaries containing data points for each packet.
        column1 (str): The column name for the byte information in the data.
        column2 (str): The column name for the timestamp information in the data.
        column3 (str): The column name for the RTT information in the data.
        window_size (float): The size of the sliding window in seconds.
        num_bins (int): The number of bins in the sliding window.
        interpolation_flag: If it is "interpld, use interpolation to calculate delivered_byte window in shift.
    """
    # list to append data for logging
    lg_delv_window = []
    lg_delv_window_at_shift = []
    lg_norm_approx = []
    lg_time_norm = []

    # Extract data
    delv_byte = [float(row[column1]) for row in data]
    time = [float(row[column2]) for row in data]
    rtt = [float(row[column3]) for row in data]

    # Determine the length of the shortest list
    min_len = np.min([len(delv_byte), len(rtt), len(time)])
    data_org = {'delv_byte': delv_byte[:min_len],
                'time': time[:min_len],
                'RTT': rtt[:min_len]}

    # Create a pandas DataFrame from the data
    df = pd.DataFrame(data_org)

    # Parameters
    # extra_bins = 2 * num_bins
    extra_bins = 15
    delv_array_bins = num_bins + extra_bins
    bin_data_delv = np.zeros(delv_array_bins)
    bin_index = 0
    bin_end_time = 0

    bin_duration = window_size / num_bins
    bin_start_time = bin_end_time
    bin_end_time += bin_duration

    # Loop through each row in the DataFrame
    for index in range(len(df)):

        # Does the current data belong to the previous bin
        if time[index] < bin_start_time:
            print("Error: Packet time is less than bin start time")
            break
        # Is the end of the last bin beyond the whole download time
        if time[-1] < bin_end_time:
            break

        # Is the packet passed the current bin
        if time[index] > bin_end_time:

            # Increase bin index and define start and end of the new bin
            bin_index += 1
            bin_start_time = bin_end_time
            bin_end_time += bin_duration

            # Does the delv window fill
            if bin_index >= num_bins:
                # Find the shift back value
                time_shifted_by_rtt = time[index] - rtt[index]
                # Find the bin_index after shifting
                bin_index_in_shift = bin_index - int((bin_end_time - time_shifted_by_rtt) / bin_duration)
                # Ensure that bin_index_in_shift is within the valid range
                if bin_index_in_shift > num_bins - 1:
                    # Do SEARCH
                    cumulative_delv_current_window = np.sum(bin_data_delv[(bin_index - num_bins):])
                    cumulative_delv_window_at_shift = np.sum(
                        bin_data_delv[(bin_index_in_shift - num_bins + 1):bin_index_in_shift + 1])

                    if interpolation_flag == "interpld":
                        cumulative_delv_window_at_shift_pre_bin = np.sum(
                            bin_data_delv[(bin_index_in_shift - num_bins):bin_index_in_shift])
                        corresponding_time_in_shift = bin_end_time - (
                                int((bin_end_time - time_shifted_by_rtt) / bin_duration) * bin_duration)
                        corresponding_time_in_shift_pre_bin = corresponding_time_in_shift - bin_duration
                        x0, x1 = corresponding_time_in_shift_pre_bin, corresponding_time_in_shift
                        y0, y1 = cumulative_delv_window_at_shift_pre_bin, cumulative_delv_window_at_shift
                        estimated_delv_value_in_shift = y0 + (time_shifted_by_rtt - x0) * (y1 - y0) / (x1 - x0)
                        cumulative_delv_window_at_shift = estimated_delv_value_in_shift
                    if cumulative_delv_window_at_shift > 0:
                        norm = ((2 * cumulative_delv_window_at_shift) - cumulative_delv_current_window) / (
                                    2 * cumulative_delv_window_at_shift)
                    else:
                        norm = 0

                    # Append data for logging
                    lg_norm_approx.append(norm)
                    lg_time_norm.append(time[index])
                    lg_delv_window.append(cumulative_delv_current_window)
                    lg_delv_window_at_shift.append(cumulative_delv_window_at_shift)

                # Does the delv array fill
                if bin_index >= delv_array_bins:
                    # Sliding the bin_data_delv array by one bin
                    bin_data_delv = np.append(bin_data_delv[1:], 0)
                    bin_index = delv_array_bins - 1

        # Add the delv_byte value to the corresponding bin
        bin_data_delv[bin_index] += delv_byte[index]

    return lg_delv_window_at_shift, lg_delv_window, lg_time_norm, lg_norm_approx


################################-------------------------------------------------###################################
# Approximate delivered byte, shift back for curr RTT, estimate sent byte at the shift time
def approximation_search1(data, column1, column2, column3, column4, window_size, num_bins, interpolation_flag):
    """
    Parameters:
        data (list): A list of dictionaries containing data points for each packet.
        column1 (str): The column name for the byte information in the data.
        column2 (str): The column name for the timestamp information in the data.
        column3 (str): The column name for the RTT information in the data.
        column4 (str): The column name for the byte information in the data.
        window_size (float): The size of the sliding window in seconds.
        num_bins (int): The number of bins in the sliding window.
        interpolation_flag: If it is "interpld, use interpolation to calculate delivered_byte window in shift.
    """
    # list to append data for logging
    lg_delv_window = []
    lg_sent_window_at_shift = []
    lg_norm_approx = []
    lg_time_norm = []

    # Extract data
    sent_byte = [float(row[column4]) for row in data]
    delv_byte = [float(row[column1]) for row in data]
    time = [float(row[column2]) for row in data]
    rtt = [float(row[column3]) for row in data]

    # Determine the length of the shortest list
    min_len = np.min([len(sent_byte), len(delv_byte), len(rtt), len(time)])
    data_org = {'sent_byte': sent_byte[:min_len],
                'delv_byte': delv_byte[:min_len],
                'time': time[:min_len],
                'RTT': rtt[:min_len]}

    # Create a pandas DataFrame from the data
    df = pd.DataFrame(data_org)

    # Determine the parameters
    extra_bins = 2 * num_bins  # Added bins to sent window to have data after shifting back by RTT
    length_sent_window = num_bins + extra_bins
    length_delv_widow = num_bins
    bin_data_sent = np.zeros(length_sent_window)  # Empty array to store the cumulative byte for each bin
    bin_data_delv = np.zeros(length_delv_widow)  # Empty array to store the cumulative byte for each bin
    bin_index_sent = 0
    bin_index_delv = 0
    bin_end_time = 0

    # Set the duration of bins
    bin_duration = window_size / num_bins
    # Set the start and end of first bin
    bin_start_time = bin_end_time
    bin_end_time += bin_duration

    # Loop through each row in the DataFrame
    for index in range(len(df)):

        # Check packet time validity
        if time[index] < bin_start_time:
            print("Error: Packet time is less than bin start time")
            break
        if time[-1] < bin_end_time:
            break

        # Is the packet passed the current bin
        if time[index] > bin_end_time:

            # Increase bin index and define start and end of the new bin
            bin_index_sent += 1
            bin_index_delv += 1
            bin_start_time = bin_end_time
            bin_end_time += bin_duration

            # Is the delivered window completed
            if bin_index_delv >= length_delv_widow:
                # Find the shift back value
                time_shifted_by_rtt = time[index] - rtt[index]
                # Find the bin_index after shifting
                bin_index_in_shift = bin_index_sent - int((bin_end_time - time_shifted_by_rtt) / bin_duration)
                # Ensure that bin_index_in_shift is within the valid range
                if bin_index_in_shift > length_delv_widow - 1:
                    # Do SEARCH
                    cumulative_delv_current_window = np.sum(bin_data_delv[(bin_index_delv - num_bins):])
                    cumulative_sent_window_at_shift = np.sum(
                        bin_data_sent[(bin_index_in_shift - num_bins + 1):bin_index_in_shift + 1])

                    if interpolation_flag == "interpld":
                        cumulative_sent_window_at_shift_pre_bin = np.sum(
                            bin_data_sent[(bin_index_in_shift - num_bins):bin_index_in_shift])
                        corresponding_time_in_shift = bin_end_time - (
                                int((bin_end_time - time_shifted_by_rtt) / bin_duration) * bin_duration)
                        corresponding_time_in_shift_pre_bin = corresponding_time_in_shift - bin_duration
                        x0, x1 = corresponding_time_in_shift_pre_bin, corresponding_time_in_shift
                        y0, y1 = cumulative_sent_window_at_shift_pre_bin, cumulative_sent_window_at_shift
                        estimated_delv_value_in_shift = y0 + (time_shifted_by_rtt - x0) * (y1 - y0) / (x1 - x0)
                        cumulative_sent_window_at_shift = estimated_delv_value_in_shift

                    if cumulative_sent_window_at_shift > 0:
                        norm = (
                                           cumulative_sent_window_at_shift - cumulative_delv_current_window) / cumulative_sent_window_at_shift

                    # Append data for logging
                    lg_norm_approx.append(norm)
                    lg_time_norm.append(time[index])
                    lg_delv_window.append(cumulative_delv_current_window)
                    lg_sent_window_at_shift.append(cumulative_sent_window_at_shift)

                # Slide window for one bin
                bin_data_delv = np.append(bin_data_delv[1:], 0)
                # Set bin_index_delv to fill the last bin again
                bin_index_delv = num_bins - 1

                # Does the delv array fill
                if bin_index_sent >= length_sent_window:
                    # Slide window for one bin
                    bin_data_sent = np.append(bin_data_sent[1:], 0)
                    # Set bin_index_sent to fill the last bin again
                    bin_index_sent = length_sent_window - 1

        # Add the delv_byte value to the corresponding bin
        bin_data_delv[bin_index_delv] += delv_byte[index]
        bin_data_sent[bin_index_sent] += sent_byte[index]

    return lg_sent_window_at_shift, lg_delv_window, lg_time_norm, lg_norm_approx


################################-------------------------------------------------###################################
# Approximate delivered byte, shift back for 'bin_factor' numbers of bin, estimate sent byte at the shift time
def approximation_search1_5(data, column1, column2, column3, column4, window_time, bin_factor):
    """
    Parameters:
        data (list): A list of dictionaries containing data points for each packet.
        column1 (str): The column name for the byte information in the data.
        column2 (str): The column name for the byte information in the data.
        column3 (str): The column name for the timestamp information in the data.
        column4 (str): The column name for the RTT information in the data.
        window_time (float): The coefficient of RTT, which, when multiplied by RTT, gives the window size..
        bin_factor (int): The factor indicating how many bins each RTT represents based on RTT
    """

    # list to append data for logging
    lg_sent_window = []
    lg_delv_window = []
    lg_norm_approx = []
    lg_time_norm = []

    # Extract data
    delv_byte = [float(row[column1]) for row in data]
    sent_byte = [float(row[column2]) for row in data]
    rtt = [float(row[column4]) for row in data]
    time = [float(row[column3]) for row in data]

    # Determine the length of the shortest list
    min_len = np.min([len(sent_byte), len(delv_byte), len(rtt), len(time)])
    data_org = {'sent_byte': sent_byte[:min_len],
                'delv_byte': delv_byte[:min_len],
                'time': time[:min_len],
                'RTT': rtt[:min_len]}

    # Create a pandas DataFrame from the data
    df = pd.DataFrame(data_org)

    # Find the number of bins based on window_time and bin_factor of RTT
    num_bin = window_time * bin_factor

    # Determine the parameters
    initial_rtt = rtt[0]
    bin_end_time = 0
    bin_index_sent = 0
    bin_index_delv = 0
    extra_bins = bin_factor  # Added bins to sent window to have data after shifting back by 'bin_factor' of bins
    length_sent_window = num_bin + extra_bins
    length_delv_window = num_bin
    bin_data_sent = np.zeros(length_sent_window)  # Empty array to store the cumulative byte for each bin
    bin_data_delv = np.zeros(num_bin)  # Empty array to store the cumulative byte for each bin
    completed_bins = 0  # Completed delivered window counter

    # Find the duration of bins
    bin_duration = initial_rtt / bin_factor
    bin_start_time = bin_end_time
    bin_end_time += bin_duration

    # Loop through each row in the DataFrame
    for index in range(len(df)):

        # Check packet time validity
        if time[index] < bin_start_time:
            print("Error: Packet time is less than bin start time")
            break
        if time[-1] < bin_end_time:
            break

        # Is the packet passed the current bin
        if time[index] > bin_end_time:

            # Set the bin size based on RTT
            bin_duration = rtt[index] / bin_factor
            # Set the bin start and send times
            bin_start_time = bin_end_time
            bin_end_time += bin_duration
            bin_index_sent += 1
            bin_index_delv += 1

            # Is there valid data for doing SEARCH
            if completed_bins >= bin_factor + 1:
                # Do SEARCH
                # Compute the cumulative bytes for the current bin_data_delv array
                cumulative_delv_byte = np.sum(bin_data_delv)
                # Compute the cumulative bytes for the sent corresponding to the shifted
                # bin_data_delv array
                cumulative_sent_byte = np.sum(bin_data_sent[:-bin_factor])

                if cumulative_sent_byte > 0:
                    # Calculate the normalized difference of sent and delivered data
                    norm = (cumulative_sent_byte - cumulative_delv_byte) / cumulative_sent_byte

                # Append data for logging
                lg_delv_window.append(cumulative_delv_byte)
                lg_sent_window.append(cumulative_sent_byte)
                lg_norm_approx.append(norm)
                lg_time_norm.append(time[index])

            # Is the delivered window completed
            if bin_index_delv >= length_delv_window:
                # Increase the counter of completed window by one
                completed_bins += 1
                # Slide window for one bin
                bin_data_delv = np.append(bin_data_delv[1:], 0)
                # Set bin_index_delv to fill the last bin again
                bin_index_delv = length_delv_window - 1

            # Is the sent window completed
            if bin_index_sent >= length_sent_window:
                # Slide window for one bin
                bin_data_sent = np.append(bin_data_sent[1:], 0)
                # Set the bin_index_sent to fill the last bin again
                bin_index_sent = length_sent_window - 1

        # Add the byte value to the corresponding bin in their corresponding array
        bin_data_sent[bin_index_sent] += sent_byte[index]
        bin_data_delv[bin_index_delv] += delv_byte[index]

    return lg_sent_window, lg_delv_window, lg_time_norm, lg_norm_approx


################################-------------------------------------------------###################################
# Approximate delivered byte by estimating last bin per each received packet, shift back for curr RTT, estimate sent byte at the shift time
def approximation_search1_per_pkt(data, column1, column2, column3, column4, window_size, num_bins):
    """
    Parameters:
        data (list): A list of dictionaries containing data points for each packet.
        column1 (str): The column name for the byte information in the data.
        column2 (str): The column name for the byte information in the data.
        column3 (str): The column name for the timestamp information in the data.
        column4 (str): The column name for the RTT information in the data.
        window_size (float): The size of the sliding window in seconds.
        num_bins (int): The number of bins in the sliding window.
    """

    # List to append data for logging
    lg_sent_window = []
    lg_delv_window = []
    lg_time_norm = []
    lg_norm_approx = []
    lg_pkt_arrival_time_in_last_bin = []
    lg_estimate_last_bin = []
    lg_all_estimate_last_bin_per_window = []
    lg_estimated_array_for_all_windows = []
    lg_actual_value_last_bins = []
    lg_time_actual_last_bin = []
    lg_actual_whole_delv_window = []

    # Extract data
    delv_byte = np.array([float(row[column1]) for row in data])
    sent_byte = np.array([float(row[column2]) for row in data])
    rtt = np.array([float(row[column4]) for row in data])
    time = np.array([float(row[column3]) for row in data])

    # Determine the length of the shortest list
    min_len = np.min([len(sent_byte), len(rtt), len(time)])
    data_org = {
        'sent_byte': sent_byte[:min_len],
        'delv_byte': delv_byte[:min_len],
        'time': time[:min_len],
        'RTT': rtt[:min_len]
    }

    # Create a pandas DataFrame from the data
    df = pd.DataFrame(data_org)

    # Determine the parameters
    extra_bins = 2 * num_bins  # Added bins to sent window to have data after shifting back by 'bin_factor' bins
    length_sent_window = num_bins + extra_bins
    length_delv_window = num_bins
    bin_data_sent = np.zeros(length_sent_window)  # Empty array to store the cumulative byte for each bin
    bin_data_delv = np.zeros(length_delv_window)  # Empty array to store the cumulative byte for each bin
    bin_index_sent = 0
    bin_index_delv = 0
    bin_end_time = 0

    # Find the duration of bins
    bin_duration = window_size / num_bins
    bin_start_time = bin_end_time
    bin_end_time += bin_duration

    # Loop through each row in the DataFrame
    for index in range(len(df)):

        # Check packet time validity
        if time[index] < bin_start_time:
            print("Error: Packet arrival time is less than start time of current bin")
            break
        if time[-1] < bin_end_time:
            break

        # Is the packet passed the current bin
        if time[index] > bin_end_time:

            # Set the bin start and send times
            bin_start_time = bin_end_time
            bin_end_time += bin_duration
            bin_index_sent += 1
            bin_index_delv += 1

            # Is the delivered window completed
            if bin_index_delv >= length_delv_window:
                lg_actual_value_last_bins.append(bin_data_delv[-1])
                lg_actual_whole_delv_window.append(np.sum(bin_data_delv))
                lg_time_actual_last_bin.append(time[index])
                lg_estimated_array_for_all_windows.append(lg_all_estimate_last_bin_per_window)
                lg_all_estimate_last_bin_per_window = []

                bin_data_delv = np.append(bin_data_delv[1:], 0)
                bin_index_delv = length_delv_window - 1

            # Is the sent window completed
            if bin_index_sent >= length_sent_window:
                bin_data_sent = np.append(bin_data_sent[1:], 0)
                bin_index_sent = length_sent_window - 1

        # Add the byte value to the corresponding bin in their corresponding array
        bin_data_sent[bin_index_sent] += sent_byte[index]
        bin_data_delv[bin_index_delv] += delv_byte[index]

        # Do SEARCH:
        # Are we in the last bin
        if bin_index_delv == length_delv_window - 1:
            # Find the shift back time
            time_shifted_by_rtt = time[index] - rtt[index]
            # Actual current bytes in the last bin
            cumulative_byte_delv_last_bin = bin_data_delv[bin_index_delv]
            # Packet arrival time in the last bin
            arrival_time_in_last_bin = time[index] - bin_start_time
            # Estimated bytes in the last bin
            estimate_delv_byte_last_bin = (cumulative_byte_delv_last_bin * bin_duration) / arrival_time_in_last_bin
            # delv byte estimation of whole window
            cumulative_byte_delv_whole_window = np.sum(bin_data_delv[:-1]) + estimate_delv_byte_last_bin
            # Find the bin_index after shifting
            bin_index_in_shift = bin_index_sent - int((bin_end_time - time_shifted_by_rtt) / bin_duration)
            # Ensure that bin_index_in_shift is within the valid range
            if bin_index_in_shift > length_delv_window - 1:
                # Compute the sent byte at the shifted time
                cumulative_sent_byte = np.sum(bin_data_sent[(bin_index_in_shift - num_bins):bin_index_in_shift])

                if cumulative_sent_byte > 0:
                    # Compute the normalization of difference between sent byte and estimated delv byte
                    norm = (cumulative_sent_byte - cumulative_byte_delv_whole_window) / cumulative_sent_byte

                # Append data for logging
                lg_sent_window.append(cumulative_sent_byte)
                lg_delv_window.append(cumulative_byte_delv_whole_window)
                lg_time_norm.append(time[index])
                lg_norm_approx.append(norm)

            # Append data for logging
            lg_estimate_last_bin.append(estimate_delv_byte_last_bin)
            lg_pkt_arrival_time_in_last_bin.append(time[index])
            lg_all_estimate_last_bin_per_window.append(estimate_delv_byte_last_bin)

    return lg_sent_window, lg_delv_window, lg_norm_approx, lg_time_norm, lg_estimate_last_bin, \
        lg_pkt_arrival_time_in_last_bin, lg_estimated_array_for_all_windows, lg_actual_value_last_bins, \
        lg_actual_whole_delv_window, lg_time_actual_last_bin


################################-------------------------------------------------###################################
# Approximate delivered byte, shift back for 'bin_factor' numbers of bin, estimate delivered byte at the shift time
def approximation_search2(data, column1, column2, column3, window_time, bin_factor):
    """
    Parameters:
        data (list): A list of dictionaries containing data points for each packet.
        column1 (str): The column name for the byte information in the data.
        column2 (str): The column name for the timestamp information in the data.
        column3 (str): The column name for the RTT information in the data.
        window_time (float): The coefficient of RTT, which, when multiplied by RTT, gives the window size..
        bin_factor (int): The factor indicating how many bins each RTT represents based on RTT
    """

    # list to append data for logging
    lg_delv_window_in_shift = []
    lg_delv_window = []
    lg_norm_approx = []
    lg_time_norm = []

    # Extract data
    delv_byte = [float(row[column1]) for row in data]
    rtt = [float(row[column3]) for row in data]
    time = [float(row[column2]) for row in data]

    # Determine the length of the shortest list
    min_len = np.min([len(delv_byte), len(rtt), len(time)])
    data_org = {'delv_byte': delv_byte[:min_len],
                'time': time[:min_len],
                'RTT': rtt[:min_len]}

    # Create a pandas DataFrame from the data
    df = pd.DataFrame(data_org)

    # Find the number of bins based on window_time and bin_factor of RTT
    num_bin = window_time * bin_factor

    # Determine the parameters
    initial_rtt = rtt[0]
    bin_end_time = 0
    bin_index_delv = 0
    extra_bins = bin_factor  # Added bins to sent window to have data after shifting back by 'bin_factor' bins
    length_delv_window = num_bin + extra_bins
    bin_data_delv = np.zeros(length_delv_window)  # Empty array to store the cumulative byte for each bin
    completed_bins = 0  # Completed delivered window counter

    # Find the duration of bins
    bin_duration = initial_rtt / bin_factor
    bin_start_time = bin_end_time
    bin_end_time += bin_duration

    # Loop through each row in the DataFrame
    for index in range(len(df)):

        # Check packet time validity
        if time[index] < bin_start_time:
            print("Error: Packet time is less than bin start time")
            break
        if time[-1] < bin_end_time:
            break

        # Is the packet passed the current bin
        if time[index] > bin_end_time:

            # Set he bin size based on RTT
            bin_duration = rtt[index] / bin_factor
            # Set the bin start and send times
            bin_start_time = bin_end_time
            bin_end_time += bin_duration
            bin_index_delv += 1

            # Is there valid data for doing SEARCH
            if completed_bins >= 1:

                # Do SEARCH
                # Compute the cumulative bytes for the current bin_data_delv array
                cumulative_delv_byte = np.sum(bin_data_delv[bin_factor:])
                # Compute the cumulative bytes for the sent corresponding to the shifted bin_data_delv array
                cumulative_delv_byte_in_shift = np.sum(bin_data_delv[:-bin_factor])

                if cumulative_delv_byte_in_shift > 0:
                    # Calculate the normalized difference of sent and delivered data
                    norm = ((2 * cumulative_delv_byte_in_shift) - cumulative_delv_byte) / (
                                2 * cumulative_delv_byte_in_shift)

                # Append data for logging
                lg_delv_window.append(cumulative_delv_byte)
                lg_delv_window_in_shift.append(cumulative_delv_byte_in_shift)
                lg_norm_approx.append(norm)
                lg_time_norm.append(time[index])

            # Is the delivered window completed
            if bin_index_delv >= length_delv_window:
                # Increase the counter of completed window by one
                completed_bins += 1
                # Slide window for one bin
                bin_data_delv = np.append(bin_data_delv[1:], 0)
                # Set bin_index_delv to fill the last bin again
                bin_index_delv = length_delv_window - 1

        # Add the byte value to the corresponding bin in their corresponding array
        bin_data_delv[bin_index_delv] += delv_byte[index]

    return lg_delv_window_in_shift, lg_delv_window, lg_time_norm, lg_norm_approx


################################-------------------------------------------------###################################
# For finding the enough num of extra bins
def approximation_search1_d_find_bins(data, column1, column2, column3, window_size, num_bins, extra_bins,
                                      interpolation_flag):
    """
    Parameters:
        data (list): A list of dictionaries containing data points for each packet.
        column1 (str): The column name for the byte information in the data.
        column2 (str): The column name for the timestamp information in the data.
        column3 (str): The column name for the RTT information in the data.
        window_size (float): The size of the sliding window in seconds.
        num_bins (int): The number of bins in the sliding window.
        interpolation_flag: If it is "interpld, use interpolation to calculate delivered_byte window in shift.
    """
    # list to append data for logging
    lg_delv_window = []
    lg_delv_window_at_shift = []
    lg_norm_approx = []
    lg_time_norm = []

    # For analysis that how many bins need to cover shift time
    enough_bin_do_search = 0  # CHANGE
    end_boundary = 0  # CHANGE
    rtt_in_bin_boundary = []

    # Extract data
    delv_byte = [float(row[column1]) for row in data]
    time = [float(row[column2]) for row in data]
    rtt = [float(row[column3]) for row in data]

    # Determine the length of the shortest list
    min_len = np.min([len(delv_byte), len(rtt), len(time)])
    data_org = {'delv_byte': delv_byte[:min_len],
                'time': time[:min_len],
                'RTT': rtt[:min_len]}

    # Create a pandas DataFrame from the data
    df = pd.DataFrame(data_org)

    # Parameters
    # extra_bins = 2 * num_bins
    delv_array_bins = num_bins + extra_bins
    bin_data_delv = np.zeros(delv_array_bins)
    bin_index = 0
    bin_end_time = 0

    bin_duration = window_size / num_bins
    bin_start_time = bin_end_time
    bin_end_time += bin_duration

    # Loop through each row in the DataFrame
    for index in range(len(df)):

        # Does the current data belong to the previous bin
        if time[index] < bin_start_time:
            print("Error: Packet time is less than bin start time")
            break
        # Is the end of the last bin beyond the whole download time
        if time[-1] < bin_end_time:
            break

        # Is the packet passed the current bin
        if time[index] > bin_end_time:

            # Increase bin index and define start and end of the new bin
            bin_index += 1
            bin_start_time = bin_end_time
            bin_end_time += bin_duration

            # Does the delv window fill
            if bin_index >= num_bins:
                # Complete bin boundaries
                end_boundary += 1
                rtt_time_in_bin_boundaries = [round(time[index], 6), round(rtt[index], 6)]
                rtt_in_bin_boundary.append(rtt_time_in_bin_boundaries)

                # Find the shift back value
                time_shifted_by_rtt = time[index] - rtt[index]
                # Find the bin_index after shifting
                bin_index_in_shift = bin_index - int((bin_end_time - time_shifted_by_rtt) / bin_duration)
                # Ensure that bin_index_in_shift is within the valid range
                if bin_index_in_shift > num_bins - 1:
                    enough_bin_do_search += 1  # CHANGE
                    # Do SEARCH
                    cumulative_delv_current_window = np.sum(bin_data_delv[(bin_index - num_bins):])
                    cumulative_delv_window_at_shift = np.sum(
                        bin_data_delv[(bin_index_in_shift - num_bins + 1):bin_index_in_shift + 1])

                    if interpolation_flag == "interpld":
                        cumulative_delv_window_at_shift_pre_bin = np.sum(
                            bin_data_delv[(bin_index_in_shift - num_bins):bin_index_in_shift])
                        corresponding_time_in_shift = bin_end_time - (
                                int((bin_end_time - time_shifted_by_rtt) / bin_duration) * bin_duration)
                        corresponding_time_in_shift_pre_bin = corresponding_time_in_shift - bin_duration
                        x0, x1 = corresponding_time_in_shift_pre_bin, corresponding_time_in_shift
                        y0, y1 = cumulative_delv_window_at_shift_pre_bin, cumulative_delv_window_at_shift
                        estimated_delv_value_in_shift = y0 + (time_shifted_by_rtt - x0) * (y1 - y0) / (x1 - x0)
                        cumulative_delv_window_at_shift = estimated_delv_value_in_shift
                    if cumulative_delv_window_at_shift > 0:
                        norm = ((2 * cumulative_delv_window_at_shift) - cumulative_delv_current_window) / (
                                    2 * cumulative_delv_window_at_shift)
                    else:
                        norm = 0

                    # Append data for logging
                    lg_norm_approx.append(norm)
                    lg_time_norm.append(time[index])
                    lg_delv_window.append(cumulative_delv_current_window)
                    lg_delv_window_at_shift.append(cumulative_delv_window_at_shift)

                # Does the delv array fill
                if bin_index >= delv_array_bins:
                    # Sliding the bin_data_delv array by one bin
                    bin_data_delv = np.append(bin_data_delv[1:], 0)
                    bin_index = delv_array_bins - 1

        # Add the delv_byte value to the corresponding bin
        bin_data_delv[bin_index] += delv_byte[index]

    return lg_delv_window_at_shift, lg_delv_window, lg_time_norm, lg_norm_approx, enough_bin_do_search, end_boundary, rtt_in_bin_boundary  # CHANGE

################################-------------------------------------------------###################################
def save_list_to_csv2(time_list1, data_list1, data_list2, data_list3, filename, header1, header2, header3, header4):
    """
        Saves the values of a list to a CSV file.

        """
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([header1, header2, header3, header4])  # Write the header row
        # for value in list:
        #     writer.writerow([value])
        for i in range(len(data_list1)):
            writer.writerow([time_list1[i], data_list1[i], data_list2[i], data_list3[i]])


#########################################################################################
# Function to extract data from a log file based on flow pointer
def find_data_both(LINE, FP):
    """
    Extracts relevant data from a list of log lines based on a given flow pointer.

    Parameters:
        LINE (List[str]): A list of log lines.
        FP (str): The flow pointer to match.

    Returns:
        A tuple of lists containing the following data: each_acked (float), now (float), ss_status (int),
        lost (int), sent_B (float), acked_B (float), cwnd (float), ssthresh (int), rtt (float).
    """
    total_byte_acked_MB = []
    now = []
    ss_status = []
    lost = []
    cwnd = []
    ssthresh = []
    rtt = []
    bin_value_MB = []
    bin_number = []
    now_time_s = []
    current_wind_MB = []
    prev_wind_MB = []
    norm = []
    bin_duration_s = []
    initial_rtt_s = []
    search_ex_time_s = []

    for line in LINE:
        if "flow pointer: " + FP + "]" in line:
            if "ACK_FUNC_INFO" in line:
                mss = int(line.split("mss ")[1].split("]")[0])
                total_byte_acked_ = int(line.split("total_byte_acked ")[1].split("]")[0]) * 1e-6  # MB
                total_byte_acked_MB.append(total_byte_acked_)
                rtt_ms_ = int(line.split("rtt_ms ")[1].split("]")[0]) * 1e-3  # ms
                rtt.append(rtt_ms_)
                num_lost_ = int(line.split("num_lost ")[1].split("]")[0])
                lost.append(num_lost_)
                cwnd_pkt_ = int(line.split("cwnd_pkt ")[1].split("]")[0]) * mss * 1e-6  # MB
                cwnd.append(cwnd_pkt_)
                ssthresh_ = int(line.split("ssthresh ")[1].split("]")[0])
                ssthresh.append(ssthresh_)
                ss_status_ = int(line.split("ss_status ")[1].split("]")[0])
                ss_status.append(ss_status_)
                now_ = float(line.split("now ")[1].split("]")[0]) * 1e-6  # second
                now.append(now_)

            if "SEARCH_INFO" in line:
                if "first_bin_duration " in line:
                    bin_duration_s.append(int(line.split("first_bin_duration ")[1].split("]")[0]) * 1e-6)  # second
                    initial_rtt_s.append(int(line.split("initialRTT ")[1].split("]")[0]) * 1e-6)  # s
                    first_time_s = int(line.split("now ")[1].split("]")[0]) * 1e-6  # second
                if "bin_value" in line:
                    bin_value_ = int(line.split("bin_value ")[1].split("]")[0]) * 1e-6  # MB
                    bin_value_MB.append(bin_value_)
                    bin_num_ = int(line.split("bin_total ")[1].split("]")[0])
                    bin_number.append(bin_num_)
                if "curr_delv" in line:
                    curr_delv_ = int(line.split("curr_delv ")[1].split("]")[0]) * 1e-6  # MB
                    current_wind_MB.append(curr_delv_)
                    prev_delv_ = int(line.split("prev_delv ")[1].split("]")[0]) * 1e-6  # MB
                    prev_wind_MB.append(prev_delv_)
                    norm_ = int(line.split("norm_100 ")[1].split("]")[0]) * 1e-2
                    norm.append(norm_)
                    now_time_ = int(line.split("now ")[1].split("]")[0]) * 1e-6  # second
                    now_time_s.append(now_time_)
                if "exit condition was met" in line:
                    search_ex_time_s_ = int(line.split("now ")[1].split("]")[0]) * 1e-6

    # Compute now_time from zero
    now_time_s = np.array(now_time_s)
    now_time_s_from_zero = now_time_s - first_time_s

    search_ex_time_s_ = search_ex_time_s_ - first_time_s
    search_ex_time_s.append(search_ex_time_s_)

    # Compute each byte delivered from total byte delivered
    total_byte_acked_MB = np.array(total_byte_acked_MB)
    each_acked = np.diff(total_byte_acked_MB)
    each_acked = np.insert(each_acked, 0, 0)
    each_acked[0] = total_byte_acked_MB[0]

    return each_acked, now, ss_status, lost, cwnd, ssthresh, rtt, total_byte_acked_MB, bin_value_MB, \
        bin_number, now_time_s_from_zero, current_wind_MB, prev_wind_MB, norm, \
        search_ex_time_s, initial_rtt_s, bin_duration_s

#########################################################################################
def plot_data_kernel(now_time_s_from_zero, current_wind_MB, prev_wind_MB, norm, exit_search, loss_time, case,
                     result_folder):
    fig, axes = plt.subplots(1, 2, figsize=(14, 6))

    # Plot the first subplot (current_wind_MB and prev_wind_MB)
    axes[0].plot(now_time_s_from_zero, current_wind_MB, marker='o', markersize=5,
                 label='current_wind')
    axes[0].plot(now_time_s_from_zero, prev_wind_MB * 2, marker='o', markersize=5,
                 label='prev_wind')
    axes[0].axvline(x=exit_search, color='g', linestyle='--', linewidth=4,
                    label=f'exit_search: {exit_search:.2f}')
    axes[0].set_xlabel('time (s)', fontsize=15)
    axes[0].set_ylabel('Volume (MB)', fontsize=15)
    axes[0].tick_params(axis='x', labelsize=17)
    axes[0].tick_params(axis='y', labelsize=17)
    axes[0].set_ylim([0, 160])
    axes[0].set_xlim([0, loss_time + 0.5])
    axes[0].legend()
    # axes[0].grid(True)
    axes[0].title.set_text('windows volumes_kernel')

    # Plot the second subplot (norm)
    axes[1].plot(now_time_s_from_zero, norm, marker='o', markersize=5)
    axes[1].axhline(y=0.35, color='r', linestyle='--', linewidth=4, label='threshold')
    axes[1].axvline(x=exit_search, color='g', linestyle='--', linewidth=4,
                    label=f'exit_search: {exit_search:.2f}')
    axes[1].axhline(y=-0, color='purple', linestyle='-', linewidth=3)
    axes[1].set_xlabel('time (s)', fontsize=15)
    axes[1].set_ylabel('norm', fontsize=15)
    axes[1].tick_params(axis='x', labelsize=17)
    axes[1].tick_params(axis='y', labelsize=17)
    axes[1].set_ylim([-1.5, 1.5])
    axes[1].set_xlim([0, loss_time + 0.5])
    axes[1].legend()
    # axes[1].grid(True)
    axes[1].title.set_text('norm_kernel')

    # Add a title for the entire figure
    # plt.suptitle(f'Case {case}', fontsize=16)

    plt.savefig(os.path.join(result_folder, f'figures_imp{case}.png'))

    # Display the figure
    plt.tight_layout(rect=[0, 0, 1, 0.96])  # Adjust the layout for the title
    # plt.show()
    plt.close()


#########################################################################################
def plot_all_with_kernel(throughput, throughput_time, twice_delv_window_at_shift, time_norm, delv_window, norm,
                         fl_latency_offset, fl_time, now_time_ms_from_zero,
                         current_wind_MB, prev_wind_MB, norm_kernel, exit_search, x_dp, x_ex_approx, x_cg_one_way_delay,
                         limit_axis, path_folder, file_name):

    # Join the directory path with the file name
    address_fig = os.path.join(path_folder, file_name)

    # Create figure with 3 rows and 2 columns
    fig, axs = plt.subplots(2, 3, figsize=(25, 15))

    # Plot the first graph
    ax1 = axs[0, 0]
    ax1.plot(throughput_time, throughput, linewidth=2, color='m', linestyle='-')
    if limit_axis[1] is not None:
        ax1.set_ylim(limit_axis[1])
    if limit_axis[0] is not None:
        ax1.set_xlim(limit_axis[0])
    ax1.tick_params(axis='x', labelsize=17)
    ax1.tick_params(axis='y', labelsize=17)
    ax1.set_xlabel('time (s)', fontsize=15)
    ax1.set_ylabel('throughput (Mbps)', fontsize=15)
    ax1.set_title('throughput over time', fontsize=15)
    # ax1.legend()

    # Plot the second graph
    ax2 = axs[0, 1]
    ax2.plot(time_norm, twice_delv_window_at_shift, marker='o', markersize=5, color='b', linestyle='-',
             label='twice_delv_window_at_shift')
    ax2.plot(time_norm, delv_window, marker='o', markersize=5, color='g', linestyle='-', label='curr_delv_window')
    if x_dp is not None:
        ax2.axvline(x_dp, linewidth=4, color='r', linestyle='--', label='Packet loss')
    if x_dp is not None:
        ax2.set_xlim([-0.1, x_dp + 0.5])
    if limit_axis[6] is not None:
        ax2.set_ylim(limit_axis[6])
    ax2.tick_params(axis='x', labelsize=17)
    ax2.tick_params(axis='y', labelsize=17)
    ax2.set_xlabel('time (s)', fontsize=15)
    ax2.set_ylabel('volume (MB)', fontsize=15)
    ax2.set_title('window volumes', fontsize=15)
    ax2.legend()

    # Plot the third graph
    ax3 = axs[0, 2]
    ax3.axhline(0, linewidth=2, color='m', linestyle='-')
    ax3.plot(time_norm, norm, marker='o', markersize=5, color='dodgerblue', linestyle='-')
    if x_dp is not None:
        ax3.axvline(x_dp, linewidth=4, color='r', linestyle='--', label=f'Packet loss = {x_dp: .2f}')
    if x_cg_one_way_delay is not None:
        ax3.axvline(x_cg_one_way_delay, linewidth=4, color='b', linestyle='--',
                    label=f'At capacity = {x_cg_one_way_delay: .2f}')
    if x_ex_approx is not None:
        ax3.axvline(x_ex_approx, linewidth=4, color='g', linestyle='--', label=f'Exit time = {x_ex_approx: .2f}')
    if x_dp is not None:
        if x_ex_approx is not None and x_ex_approx >= x_dp:
            ax3.set_xlim([-0.1, x_ex_approx + 0.5])
        else:
            ax3.set_xlim([-0.1, x_dp + 0.5])
    if limit_axis[7] is not None:
        ax3.set_ylim(limit_axis[7])
    ax3.tick_params(axis='x', labelsize=17)
    ax3.tick_params(axis='y', labelsize=17)
    ax3.set_xlabel('norm', fontsize=15)
    ax3.set_ylabel('time (s)', fontsize=15)
    ax3.set_title('norm_kernel', fontsize=15)
    ax3.legend()

    # Plot the forth graph
    ax4 = axs[1, 0]
    ax4.plot(fl_time, fl_latency_offset, color='darkcyan', linewidth=2)
    if x_dp is not None:
        ax4.axvline(x_dp, linewidth=4, color='r', linestyle='--', label=f'Packet loss = {x_dp: .2f}')
    if limit_axis[4] is not None:
        ax4.set_ylim(limit_axis[4])
    if limit_axis[5] is not None:
        ax4.set_xlim(limit_axis[5])
    if x_cg_one_way_delay is not None:
        ax4.axvline(x_cg_one_way_delay, linewidth=4, color='b', linestyle='--',
                    label=f'At capacity = {x_cg_one_way_delay: .2f}')
    ax4.tick_params(axis='x', labelsize=17)
    ax4.tick_params(axis='y', labelsize=17)
    ax4.set_xlabel('time (s)', fontsize=15)
    ax4.set_ylabel('FL Latency Offset', fontsize=15)
    ax4.set_title('One_way delay', fontsize=15)
    ax4.legend()

    # Plot the fifth graph
    ax5 = axs[1, 1]
    ax5.plot(now_time_ms_from_zero, current_wind_MB, marker='o', markersize=5,
             label='current_wind')
    ax5.plot(now_time_ms_from_zero, prev_wind_MB * 2, marker='o', markersize=5,
             label='prev_wind')
    ax5.axvline(x=exit_search, color='g', linestyle='--', linewidth=4,
                label=f'exit_search: {exit_search:.2f}')
    ax5.set_xlabel('time (s)', fontsize=15)
    ax5.set_ylabel('Volume (MB)', fontsize=15)
    ax5.tick_params(axis='x', labelsize=17)
    ax5.tick_params(axis='y', labelsize=17)
    ax5.set_ylim([0, 160])
    ax5.set_xlim([0, x_dp + 0.5])
    ax5.legend()
    # axes[0].grid(True)
    ax5.set_title('windows volumes_kernel', fontsize=15)

    # Plot the sixth graph
    ax6 = axs[1, 2]
    ax6.plot(now_time_ms_from_zero, norm_kernel, marker='o', markersize=5)
    ax6.axhline(y=0.35, color='r', linestyle='--', linewidth=4, label='threshold')
    ax6.axvline(x=exit_search, color='g', linestyle='--', linewidth=4,
                label=f'exit_search: {exit_search:.2f}')
    ax6.axhline(y=-0, color='purple', linestyle='-', linewidth=3)
    ax6.set_xlabel('time (s)', fontsize=15)
    ax6.set_ylabel('norm', fontsize=15)
    ax6.tick_params(axis='x', labelsize=17)
    ax6.tick_params(axis='y', labelsize=17)
    ax6.set_ylim([-1.5, 1.5])
    ax6.set_xlim([0, x_dp + 0.5])
    ax6.legend()
    # axes[1].grid(True)
    ax6.set_title('norm_kernel', fontsize=15)

    # Adjust spacing and position of subplots
    fig.subplots_adjust(left=0.1, right=0.9, bottom=0.1, top=0.9, wspace=0.4, hspace=0.4)
    # Save the figure to the specified file path and show it
    plt.savefig(address_fig, bbox_inches='tight')
    plt.close()

#########################################################################################
# Function to extract data from a log file based on flow pointer
def find_data_new(LINE, FP):
    """
    Extracts relevant data from a list of log lines based on a given flow pointer.

    Parameters:
        LINE (List[str]): A list of log lines.
        FP (str): The flow pointer to match.

    Returns:
        A tuple of lists containing the following data: each_acked (float), now (float), ss_status (int),
        lost (int), sent_B (float), acked_B (float), cwnd (float), ssthresh (int), rtt (float).
    """
    total_byte_acked_MB = []
    now = []
    ss_status = []
    lost = []
    cwnd = []
    ssthresh = []
    rtt = []

    for line in LINE:
        if "flow pointer: " + FP + "]" in line:
            if "ACK_FUNC_INFO" in line:
                mss = int(line.split("mss ")[1].split("]")[0])
                total_byte_acked_ = int(line.split("total_byte_acked ")[1].split("]")[0]) * 1e-6  # MB
                total_byte_acked_MB.append(total_byte_acked_)
                rtt_ms_ = int(line.split("rtt_ms ")[1].split("]")[0]) * 1e-3  # ms
                rtt.append(rtt_ms_)
                num_lost_ = int(line.split("num_lost ")[1].split("]")[0])
                lost.append(num_lost_)
                cwnd_pkt_ = int(line.split("cwnd_pkt ")[1].split("]")[0]) * mss * 1e-6  # MB
                cwnd.append(cwnd_pkt_)
                ssthresh_ = int(line.split("ssthresh ")[1].split("]")[0])
                ssthresh.append(ssthresh_)
                ss_status_ = int(line.split("ss_status ")[1].split("]")[0])
                ss_status.append(ss_status_)
                now_ = float(line.split("now ")[1].split("]")[0]) * 1e-6  # second
                now.append(now_)


    # Compute each byte delivered from total byte delivered
    total_byte_acked_MB = np.array(total_byte_acked_MB)
    each_acked = np.diff(total_byte_acked_MB)
    each_acked = np.insert(each_acked, 0, 0)
    each_acked[0] = total_byte_acked_MB[0]

    return each_acked, now, ss_status, lost, cwnd, ssthresh, rtt, total_byte_acked_MB
