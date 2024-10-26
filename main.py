import argparse
import asyncio
import socket
from lib.run import Run
from lib.targets import RemoteTarget, LocalTarget
from lib.util import RunConfig, int_or_none
import getpass


# CONFIGURE THE SCRIPT HERE
async def run_tool(passwd: str):
    print("running tool")

    runs = []

    for _ in range(10):
        runs.append(RunConfig(hystartEnabled=False, searchMode="0", iPerfTime=3))
        runs.append(RunConfig(hystartEnabled=False, searchMode="1", iPerfTime=3))
        runs.append(RunConfig(hystartEnabled=True, searchMode="1", iPerfTime=3))

    # Example running a local-remote configuration
    run = Run(
        clientTarget=RemoteTarget(
            sshIp="mlcnetb.cs.wpi.edu",
            remote_addr=socket.gethostbyname(socket.gethostname()),
            sshUsername="cmtam",
            interface="ens2",
            password=passwd,
        ),
        serverTarget=LocalTarget(interface="en0", remote_addr="mlcnetb.cs.wpi.edu"),
        runs=runs,
        timeBetweenRuns=5,
        memo="Unity outside 343",
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

    await run.start()


def parse_args():
    parser = argparse.ArgumentParser()

    # Arguments that the user should run
    parser.add_argument(
        "-t", "--tool", help="runs the script in tool mode", action="store_true"
    )
    parser.add_argument(
        "-m",
        "--schedule",
        type=int,
        help="schedule the script to run every M minutes",
        default=-1,
    )
    parser.add_argument("-x", "--password", help="provides the password to the script")

    # Arguments that are used when the target runs as a server or client
    parser.add_argument("-i", "--interface", help="interface to listen on")
    parser.add_argument("-s", "--server", help="run server", action="store_true")
    parser.add_argument("-c", "--client", help="connect to the specified address")
    parser.add_argument(
        "-p", "--port", help="the port to use to host or connect", default="5235"
    )
    parser.add_argument("--hystart", help="enable hystart", default=False)
    parser.add_argument("--search", help="set search start mode", default=2)
    parser.add_argument("--runTime", help="set how long iperf will run for")
    parser.add_argument(
        "--runSize",
        help="set threshold to stop iperf after X amount of bytes are transmit",
    )

    return parser.parse_args()


async def run_client_server():

    runConfig = RunConfig(
        hystartEnabled=args.hystart,
        searchMode=args.search,
        iPerfTime=int_or_none(args.runTime),
        iPerfSize=int_or_none(args.runSize),
    )

    if args.client:
        print("Running local client")
        await LocalTarget(args.interface, args.client).runClient(runConfig)
    elif args.server:
        print("Running server")
        await LocalTarget(args.interface, "").runServer(runConfig)
    else:
        print(
            "No operation performed. Did you mean to run the script in tool (-t) mode?"
        )


def get_password():
    if not args.password:
        passwd = getpass.getpass()
    else:
        passwd = args.password
    return passwd


if __name__ == "__main__":

    args = parse_args()

    # Tool mode is when the script is the 3rd party controller of the server/client.
    # If we're not in tool mode, we run the server/client.
    # You as the user should invoke the script in 'tool' mode by adding the '-t' flag.
    if args.tool:
        p = get_password()

        if args.schedule <= 0:
            asyncio.get_event_loop().run_until_complete(run_tool(p))
        else:
            from apscheduler.schedulers.asyncio import AsyncIOScheduler

            scheduler = AsyncIOScheduler()
            scheduler.add_job(
                run_tool, args=[p], trigger="interval", minutes=args.schedule
            )
            scheduler.start()
            print("Press CTRL+C to exit")

            try:
                asyncio.get_event_loop().run_forever()
            except (KeyboardInterrupt, SystemExit):
                pass

    else:
        asyncio.get_event_loop().run_until_complete(run_client_server())
