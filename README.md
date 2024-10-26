# C2024 ISP w/ Claypool

## How to gather data

### 1. Install the neccessary packages

```bash
pip install apscheduler asyncssh
```

### 2. Ensure your sshkey is uploaded to the servers `authorized_keys` you are SSHing into

### 3. Configure the script in `main.py`

```python
# CONFIGURE THE SCRIPT HERE
async def run_tool(passwd: str):
    print("running tool")

    runs = []

    # The following is an example of how to run the tool with different configurations
    for _ in range(10):
        runs.append(RunConfig(hystartEnabled=False, searchMode="0", iPerfTime=3))
        runs.append(RunConfig(hystartEnabled=False, searchMode="1", iPerfTime=3))
        runs.append(RunConfig(hystartEnabled=True, searchMode="1", iPerfTime=3))

    # Example running a local-remote configuration
    run = Run(
        clientTarget=RemoteTarget(      # The target that will be downloading the file
            sshIp="mlcnetb.cs.wpi.edu", # The IP of the sshserver to connect to
            remote_addr=socket.gethostbyname(socket.gethostname()), # The IP of the client to connect to
            sshUsername="cmtam",        # Your username on the remote machine
            interface="ens2",           # The interface of the remote machine to record packets on
            password=passwd,
        ),                              # The target that will be uploading the file
        serverTarget=LocalTarget(interface="en0", remote_addr="mlcnetb.cs.wpi.edu"),
        runs=runs,
        timeBetweenRuns=5,              # The time to wait between runs
        memo="Unity outside 343",       # The memo the run will be saved with (a note)
    )

    # Example running a remote-remote configuration
    # run = Run(
    #     RemoteTarget(
    #         sshIp="mlcneta.cs.wpi.edu",
    #         sshUsername="cmtam",
    #         interface="ens2",
    #         remote_addr="mlcnetb.cs.wpi.edu",
    #         password=password,
    #     ),
    #     RemoteTarget(
    #         sshIp="mlcnetb.cs.wpi.edu",
    #         sshUsername="cmtam",
    #         interface="ens2",
    #         password=password,
    #     ),
    #     maxIterations=1,
    # )
```

### 4. Run the script

```bash
python3 main.py -t -x YOURPASSWORD
```

`-t` - Runs the script in "tool" remote, which acts like the coordinator between the two targets
`-x` - The password passed into the `run_tool` function above. Usually to elevate permissions on the remote machine.

### 5. View outputs

Outputs will be saved in the `logs` directory in the `isp_scripts` folder.

## Analyzing the Data

### 1. Install the neccessary packages

```bash
pip install pandas matplotlib pyxlsb
```

### 2. Run the analysis script

```bash
python3 scripts/convert_files.py # This will graph, compute averages and standard deviations, and save the data to a csv. View the output data in `logs/<YOUR RUN>/pcap_data`. If you need to rerun, delete `processed.txt` in the log subdirectory.

python3 scripts/graph_throughputs.py # This will graph the throughputs of the data in `logs/<YOUR RUN>/pcap_data`. View the output data in `logs/<YOUR RUN>/graphs`.
```
