from abc import abstractmethod
import asyncio
import os
from lib.util import DEFAULT_PORT
from lib.main_run import run_server, run_client
from lib.run import RunConfig


class Target:
    """
    A abstract class that represents a target machine for the test.
    """

    def get_local_addr(self):
        """
        Get the address of the local machine.
        """
        return None

    def get_remote_addr(self):
        """
        Get the address of the remote machine.
        """
        return None

    async def run_cmd(self, cmd: str, *args):
        """
        Runs a command on this machine.
        """
        process = await asyncio.subprocess.create_subprocess_exec(cmd, *args)
        await process.wait()

    async def run_shell_cmd(self, cmd: str):
        """
        Runs a shell command on this machine.
        """
        process = await asyncio.subprocess.create_subprocess_shell(cmd)
        await process.wait()

    @abstractmethod
    def runServer(self, runConfig: RunConfig):
        """
        Runs the server side of the test on the target machine.
        """
        pass

    @abstractmethod
    def runClient(self, runConfig: RunConfig):
        """
        Runs the client side of the test on the target machine.
        """
        pass

    @abstractmethod
    def saveLogs(self, outputPath: str):
        """
        Saves the logs from the target machine to the specified output path.

        Args:
            outputPath: The path to save the logs to.
        """
        pass

    @abstractmethod
    def setup(self):
        """
        Setup the target machine before the test.
        """
        pass

    @abstractmethod
    def cleanup(self):
        """
        Cleans up the target machine after the test.
        """
        pass


class RemoteTarget(Target):
    """
    A class that represents a remote target machine for the test.

    Args:
        sshIp: The SSH host to connect to.
        interface: The interface to listen on.
        remote_addr: The remote address to connect to.
        password: The password to use for the SSH connection.
        port: The port to connect to.
    """

    conn = None

    def __init__(
        self,
        sshIp: str = None,
        sshUsername: str = None,
        interface: str = None,
        remote_addr: str = None,
        password: str = None,
        port: str = DEFAULT_PORT,
    ) -> None:

        self.sshIp = sshIp
        self.sshUsername = sshUsername
        self.interface = interface
        self.remote_addr = remote_addr
        self.password = password
        self.port = port
        self.sshHost = f"{self.sshUsername}@{self.sshIp}"

    def get_local_addr(self):
        return self.sshIp

    def get_remote_addr(self):
        return self.remote_addr

    async def run_remote_cmd(self, cmd: str, sudo: bool = False):
        print("running remote cmd:", cmd)
        if sudo:
            cmd = f"echo {self.password} | sudo -S {cmd}"
        process = await self.conn.create_process(cmd)

        async for line in process.stdout:
            print("remote:", line, end="")

    async def __copyFilesToRemote(self):
        await self.run_shell_cmd(
            f"zip -q -r - main.py __main__.py lib | ssh {self.sshHost} 'cat > app.zip'",
        )

    async def runServer(self, runConfig: RunConfig):
        await self.run_remote_cmd(
            f"python3 app.zip -s -i {self.interface} --hystart {runConfig.hystartEnabled} --search {runConfig.searchMode} --runTime {runConfig.iPerfTime} --runSize {runConfig.iPerfSize}",
            sudo=True,
        )

    async def runClient(self, runConfig: RunConfig):
        await self.run_remote_cmd(
            f"python3 app.zip -c {self.remote_addr} -p {self.port} -i {self.interface} --hystart {runConfig.hystartEnabled} --search {runConfig.searchMode} --runTime {runConfig.iPerfTime} --runSize {runConfig.iPerfSize}",
            sudo=True,
        )

    async def saveLogs(self, outputPath: str):
        os.makedirs(outputPath, exist_ok=True)
        await self.run_shell_cmd(f"scp {self.sshHost}:~/*.{{log,pcap}} '{outputPath}'")

    async def __setup_ssh(self):
        import asyncssh

        await self.__copyFilesToRemote()

        self.conn = await asyncssh.connect(
            self.sshIp, username=self.sshUsername, password=self.password
        )

    async def setup(self):
        if self.conn is None:
            await self.__setup_ssh()

        await self.run_remote_cmd(f"pkill python3", sudo=True)
        await self.run_remote_cmd(f"pkill iperf3", sudo=True)

    async def cleanup(self):
        await self.run_remote_cmd("rm *.{log,pcap}")


class LocalTarget(Target):
    """
    A class that represents a local machine for the test.
    """

    def __init__(
        self,
        interface: str = None,
        remote_addr=None,
        port=DEFAULT_PORT,
    ) -> None:
        """
        Args:
            interface: The interface to listen on.
            remote_addr: The remote address to connect to.
            port: The port to connect to.
        """
        self.interface = interface
        self.remote_addr = remote_addr
        self.port = port

    def get_local_addr(self):
        return "localhost"

    def get_remote_addr(self):
        return self.remote_addr

    async def runServer(self, runConfig: RunConfig):
        await run_server(self.interface, self.port, runConfig)

    async def runClient(self, runConfig: RunConfig):
        await run_client(self.interface, self.remote_addr, self.port, runConfig)

    async def saveLogs(self, outputPath: str):
        os.makedirs(outputPath, exist_ok=True)
        await self.run_shell_cmd(f"cp *.{{log,pcap}} '{outputPath}'")

    async def setup(self):
        await self.run_shell_cmd("pkill python3 && pkill iperf3")

    async def cleanup(self):
        await self.run_shell_cmd("rm *.{log,pcap}")
