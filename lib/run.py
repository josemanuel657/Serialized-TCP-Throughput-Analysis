import os
from lib.util import DEFAULT_WAIT_FOR_SERVER_START, RunConfig
from lib.targets import Target
import asyncio
from typing import List
import json
from datetime import datetime


class Run:
    """
    A class that represents a run of the test.
    """

    clientTarget: Target
    serverTarget: Target
    iterationNumber: int
    timeBetweenRuns: int
    runStartTime: datetime
    runEndTime: datetime
    startTime: datetime
    endTime: datetime
    logDir: str = "logs"
    runs: List[RunConfig]
    memo: str

    hystartEnabled: bool
    searchMode: int

    def __init__(
        self,
        clientTarget: Target = None,
        serverTarget: Target = None,
        timeBetweenRuns: int = 5,
        runs: List[RunConfig] = [],
        memo: str = "No memo provided.",
    ):
        """
        Args:
            clientTarget: The client target for the test.
            serverTarget: The server target for the test.
            timeBetweenRuns: The time to wait between runs.
            runs: A list of RunConfig objects that specify the parameters for each run.
        """
        self.clientTarget = clientTarget
        self.serverTarget = serverTarget
        self.timeBetweenRuns = timeBetweenRuns
        self.currentIteration = 1
        self.runs = runs
        self.memo = memo

    def getRunSubfolderName(self, isServer: bool = False):
        """
        Creates a folder name for the logs.

        The folder name is in the following format:
        <prefix>/<start_time>/run<iteration>_<platform>_<time>/server|client

        Args:
            prefix: The prefix for the folder name.
            isServer: Whether the logs are for the server or the client.
        """
        return os.path.join(
            self.getLogFolderName(),
            "server" if isServer else "client",
        )

    def getLogFolderName(self):
        """
        Creates a folder name for the logs.
        """
        return os.path.join(
            self.logDir,
            self.startTime.strftime("%Y-%m-%d_%H:%M:%S"),
            f"run{self.currentIteration}",
        )

    def create_md(self):
        path = os.path.join(self.getLogFolderName(), "RUN_INFO.md")

        with open(path, "w") as f:
            f.write(create_readme_string(self))

    def create_json(self):
        path = os.path.join(self.getLogFolderName(), "RUN_INFO.json")

        with open(path, "w") as f:
            config = self.getCurrentRun().to_dict()

            config["startTime"] = self.runStartTime.strftime("%Y-%m-%d %H:%M:%S")
            config["endTime"] = self.runEndTime.strftime("%Y-%m-%d %H:%M:%S")
            config["memo"] = self.memo

            f.write(json.dumps(config, indent=4))

    def getCurrentRun(self):
        return self.runs[self.currentIteration - 1]

    async def do_run(self):
        """
        Performs a single run of the test.
        """
        run_config = self.getCurrentRun()

        await self.clientTarget.setup()
        await self.serverTarget.setup()

        # Runs the server asynchronously
        task = asyncio.ensure_future(self.serverTarget.runServer(run_config))
        # Wait for the server to start
        await asyncio.sleep(DEFAULT_WAIT_FOR_SERVER_START)

        self.runStartTime = datetime.now()
        print("test3")

        await self.clientTarget.runClient(run_config)
        # Wait for server to finish
        await task
        print("test1")

        self.runEndTime = datetime.now()

        await self.clientTarget.saveLogs(self.getRunSubfolderName(False))
        await self.serverTarget.saveLogs(self.getRunSubfolderName(True))

        self.create_md()
        self.create_json()

        await self.clientTarget.cleanup()
        await self.serverTarget.cleanup()

    async def start(self):
        """
        Runs the tests
        """
        if self.runs is None or len(self.runs) == 0:
            raise ValueError("No runs specified")

        self.startTime = datetime.now()

        while True:
            print(
                f"Starting iteration {self.currentIteration} with parameters: {self.getCurrentRun()}"
            )

            await self.do_run()

            if self.currentIteration >= len(self.runs):
                break

            print(
                f"Iteration {self.currentIteration} complete. Waiting {self.timeBetweenRuns}s for next run."
            )

            self.currentIteration += 1
            await asyncio.sleep(self.timeBetweenRuns)

        self.endTime = datetime.now()


def check_and_read(path: str) -> str:
    """
    Checks if the file exists and reads it if it does. Otherwise, returns "Unknown".
    """
    if os.path.exists(path):
        with open(path) as f:
            return f.read().strip()
    return "Unknown"


def create_readme_string(run: Run) -> str:
    """
    Creates a README string for the test.
    """
    client_path = run.getRunSubfolderName(False)
    server_path = run.getRunSubfolderName(True)

    return f"""
# SEARCH Capture

{run.memo}

## Run Information

**Start Time**: {run.runStartTime.strftime("%Y-%m-%d %H:%M:%S")}
**End Time**: {run.runEndTime.strftime("%Y-%m-%d %H:%M:%S")}

**Elapsed Time**: {(run.runEndTime - run.runStartTime).total_seconds()} seconds

**Run Config:**

```json
{json.dumps(run.getCurrentRun().to_dict(), indent=4)}
```

### iPerf Information

```bash
{check_and_read(os.path.join(client_path, "iperf3.log"))}
```

## System Information

### Client

{run.clientTarget.get_local_addr()}

Congestion Control: `{check_and_read(os.path.join(client_path, "congestion_control.log"))}`

#### Kernel Info

```bash
{check_and_read(os.path.join(client_path, "os.log"))}
```

#### CPU Info

```bash
{check_and_read(os.path.join(client_path, "cpuinfo.log"))}
```

#### Wifi Info

```bash
{check_and_read(os.path.join(client_path, "wifi.log"))}
```

#### Battery Info

```bash
{check_and_read(os.path.join(client_path, "battery.log"))}
```

### Server
{run.clientTarget.get_remote_addr()}

Congestion Control: `{check_and_read(os.path.join(server_path, "congestion_control.log"))}`

#### Kernel Info

```bash
{check_and_read(os.path.join(server_path, "os.log"))}
```

#### CPU Info

```bash
{check_and_read(os.path.join(server_path, "cpuinfo.log"))}
```

#### Wifi Info

```bash
{check_and_read(os.path.join(server_path, "wifi.log"))}
```

#### Battery Info

```bash
{check_and_read(os.path.join(server_path, "battery.log"))}
```

"""
