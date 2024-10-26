from io import BufferedReader
from lib.process import SEARCHProcess
import os
import time
import platform

from datetime import datetime, timedelta


class iPerf:
    """
    A wrapper around the iperf3 process.
    """

    process: SEARCHProcess

    @classmethod
    async def start(
        cls,
        port: str,
        address: str = None,
        timeToRun: int = 10,
        bytesToTransmit: int = None,
    ):
        self = cls()

        if address is None:
            # Start server
            self.process = SEARCHProcess(
                "iperf3",
                "-s",
                "-p",
                port,
                "-1",
                "--forceflush",
                useSleepRead=True,
                autoLog=False,
            )
        else:
            # Determine whether to run for a set time or a set number of blocks
            arg = None
            value = None

            if bytesToTransmit:
                arg = "-n"
                value = str(bytesToTransmit)
            elif timeToRun:
                arg = "-t"
                value = str(timeToRun)

            # Start client
            self.process = SEARCHProcess(
                "iperf3",
                "-c",
                address,
                "-p",
                port,
                "--forceflush",
                arg,
                value,
                useSleepRead=True,
                autoLog=False,
            )

        await self.process.start()

        return self

    async def waitForConnection(self):
        """
        Waits for a client to connect to the server.
        """
        await self.process.waitForString("Accepted")

    async def waitForCompletion(self):
        """
        Waits for the iperf process to complete.
        """
        await self.process.waitForString("receiver")


class Ping:
    process: SEARCHProcess

    @classmethod
    async def start(cls, address: str, time_between="0.2"):
        self = cls()
        self.process = await SEARCHProcess(
            "ping",
            "-i",
            time_between,
            address,
            logCallback=Ping.logCallback,
        ).start()

        return self

    def logCallback(line: str):
        return line.strip() + " ts=" + str(time.time()) + "\n"


class TCPDump:
    process: SEARCHProcess

    @classmethod
    async def start(cls, interface: str, filter_str: str):
        """
        Starts tshark with a filter.

        Args:
            interface: The interface to listen on.
            filter_str: The filter string to use.
        """
        self = cls()
        self.process = SEARCHProcess(
            "tcpdump",
            "-i",
            interface,
            "-s",
            "96",
            "-w",
            "output.pcap",
            filter_str,
        )
        await self.process.start()

        return self

    def stop(self):
        self.process.stop()

    async def wait_until_complete(self):
        await self.process.wait()


class KernLog:
    f: BufferedReader

    @classmethod
    async def start(cls):
        """
        Opens /var/log/kern.log and holds the file pointer
        """
        self = cls()

        self.f = open("/var/log/kern.log", "rb")
        self.f.seek(0, os.SEEK_END)

        return self

    async def stop(self):
        """
        Reads the rest of the file and closes it.
        """
        with open("kern.log", "wb") as f:
            f.write(self.f.read())


class WifiLog:
    process: SEARCHProcess

    @classmethod
    async def start(cls):
        self = cls()
        self.process = SEARCHProcess(
            "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport",
            "-I",
            "/var/log/wifi.log",
            enableLogging="wifi.log",
        )
        await self.process.start()
        return self


class HardwareInfo:
    @classmethod
    async def start(cls):
        self = cls()

        if platform.system() == "Linux":
            await SEARCHProcess(
                "cat",
                "/proc/cpuinfo",
                enableLogging="cpuinfo.log",
            ).start_and_wait()

            await SEARCHProcess(
                "cat",
                "/proc/sys/net/ipv4/tcp_congestion_control",
                enableLogging="congestion_control.log",
            ).start_and_wait()

        elif platform.system() == "Darwin":
            await SEARCHProcess(
                "system_profiler",
                "SPHardwareDataType",
                enableLogging="cpuinfo.log",
            ).start_and_wait()

            await SEARCHProcess(
                "pmset",
                "-g",
                "batt",
                enableLogging="battery.log",
            ).start_and_wait()

        await SEARCHProcess(
            "uname",
            "-a",
            enableLogging="os.log",
        ).start_and_wait()

        return self


class Setup:
    def set_hystart(enabled: bool):
        os.system(
            f"echo {1 if enabled else 0} | sudo tee /sys/module/tcp_cubic/parameters/hystart"
        )
        os.system(
            f"echo {1 if enabled else 0} | sudo tee /sys/module/tcp_cubic_search/parameters/hystart"
        )

    def set_search(mode: int):
        """
        Mode is an integer:
        0: Disabled (no logging)
        1: Enabled with exit from slow start
        2: Enabled without exit from slow start
        """
        os.system(f"sudo sysctl -w net.ipv4.tcp_congestion_control=cubic_search")
        os.system(
            f"echo {mode} | sudo tee /sys/module/tcp_cubic_search/parameters/search"
        )

    def set_tcp_buffer_size():
        os.system("sudo sysctl -w net.ipv4.tcp_wmem='4096 2000000 64000000'")
