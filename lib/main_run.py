import platform
from lib.cmds import *
from lib.run import RunConfig


async def run_server(
    interface: str,
    port: str,
    runConfig: RunConfig,
):
    """
    Runs the server side of the test.

    Args:
        interface: The interface to listen on.
        port: The port to listen on.
    """
    print(f"Listening on {port}")

    kernlog = None

    if platform.system() == "Linux":
        Setup.set_tcp_buffer_size()
        Setup.set_hystart(runConfig.hystartEnabled)
        Setup.set_search(runConfig.searchMode)
        kernlog = await KernLog.start()
    elif platform.system() == "Darwin":  # MacOS
        await WifiLog.start()

    await HardwareInfo.start()
    tcpdump = await TCPDump.start(interface, f"port {port}")

    iperf = await iPerf.start(port)
    await iperf.waitForConnection()

    print("server: Got iperf connection")

    await iperf.waitForCompletion()

    tcpdump.stop()  # Stop TCPDump for a graceful shutdown

    if platform.system() == "Linux":
        await kernlog.stop()

    print("server: Done!")


async def run_client(interface: str, address: str, port: str, runConfig: RunConfig):
    """
    Runs the client side of the test.

    Args:
        interface: The interface to listen on.
        address: The address to connect to.
        port: The port to connect to.
    """
    tcpdump = await TCPDump.start(interface, f"port {port}")
    await Ping.start(address)
    await HardwareInfo.start()
    kernlog = None

    if platform.system() == "Linux":
        Setup.set_tcp_buffer_size()
        Setup.set_hystart(runConfig.hystartEnabled)
        Setup.set_search(runConfig.searchMode)
        kernlog = await KernLog.start()
    elif platform.system() == "Darwin":  # MacOS
        await WifiLog.start()

    # Wait until server starts
    # await wait_for_port(int(port), address, DEFAULT_TIMEOUT)

    iperf = await iPerf.start(
        port,
        address,
        timeToRun=runConfig.iPerfTime,
        bytesToTransmit=runConfig.iPerfSize,
    )

    print("client: waiting for iperf completion")

    await iperf.waitForCompletion()

    tcpdump.stop()  # Stop TCPDump for a graceful shutdown

    if platform.system() == "Linux":
        await kernlog.stop()

    print("client: Done!")
