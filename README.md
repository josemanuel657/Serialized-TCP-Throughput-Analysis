# Serialized-TCP-Throughput-Analysis

## Project Overview

This project involves testing and analyzing a TCP Congestion Control algorithm designed to optimize network throughput, specifically for high-latency satellite connections. Developed in collaboration with Prof. Claypool and PhD candidate Maryam Ataei, the algorithm aims to improve upon the traditional Hystart algorithm by adjusting the slow-start phase to exit just before packet loss occurs, thereby enhancing overall network performance.

The included scripts automate the process of configuring and running network experiments, gathering performance metrics, and analyzing the results. By simplifying experiment setup, data collection, and analysis, these scripts allow for efficient comparisons between different algorithm configurations and facilitate detailed insights into network performance.

## Why These Scripts Are Useful

These Python scripts are designed to streamline the entire data collection and analysis workflow for network throughput experiments:
- **Automates Experiment Setup**: Simplifies configuration and scheduling of network tests, reducing manual input.
- **Facilitates Data Collection**: Uses SSH, `iperf3`, and PCAP files to capture detailed performance data across network sites.
- **Enables Analysis and Visualization**: Converts data into graphs and statistical summaries, making it easy to evaluate and visualize results for different configurations.

## How to Gather Data

### 1. Install the Necessary Packages

Before running the scripts, ensure you have the following packages installed:

```bash
pip install apscheduler asyncssh
```

### 2. Set Up SSH Access

Upload your SSH key to the `authorized_keys` file on the servers you will be SSHing into. This allows the script to connect to the remote machines for data collection.

### 3. Configure the Script in `main.py`

Edit the configurations in `main.py` to set up the experiment parameters, such as the targets (local or remote), the number of runs, and specific settings for the TCP Congestion Control algorithm.

Example configuration:

```python
# CONFIGURE THE SCRIPT HERE
async def run_tool(passwd: str):
    print("running tool")

    runs = []

    # Example configurations for different runs
    for _ in range(10):
        runs.append(RunConfig(hystartEnabled=False, searchMode="0", iPerfTime=3))
        runs.append(RunConfig(hystartEnabled=False, searchMode="1", iPerfTime=3))
        runs.append(RunConfig(hystartEnabled=True, searchMode="1", iPerfTime=3))

    # Set up local-remote and remote-remote configurations
    run = Run(
        clientTarget=RemoteTarget(sshIp="mlcnetb.cs.wpi.edu", sshUsername="cmtam", interface="ens2", password=passwd),
        serverTarget=LocalTarget(interface="en0", remote_addr="mlcnetb.cs.wpi.edu"),
        runs=runs,
        timeBetweenRuns=5,
        memo="Unity outside 343",
    )
```

### 4. Run the Script

Execute the script with the following command:

```bash
python3 main.py -t -x YOURPASSWORD
```

- `-t` runs the script in "tool" mode, coordinating between the two targets.
- `-x` passes the password required for SSH connections and permissions.

### 5. View Outputs

Outputs will be saved in the `logs` directory under `isp_scripts`. Each experiment's data, including configuration details and performance logs, will be stored here for analysis.

## Analyzing the Data

### 1. Install Additional Packages for Analysis

Ensure you have the required packages for data analysis and visualization:

```bash
pip install pandas matplotlib pyxlsb
```

### 2. Run the Analysis Scripts

- **Convert and Analyze Data**:
  ```bash
  python3 scripts/convert_files.py
  ```
  This script computes averages, standard deviations, and graphs, saving processed data to `logs/<YOUR RUN>/pcap_data`.

- **Graph Throughput Data**:
  ```bash
  python3 scripts/graph_throughputs.py
  ```
  This script generates graphs of throughput data, saved in `logs/<YOUR RUN>/graphs`.

Use these scripts to compare configurations and visualize the impact of the modified TCP Congestion Control algorithm on network throughput.
