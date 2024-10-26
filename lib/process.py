import asyncio
from io import BufferedWriter
from typing import List
import contextlib


class SEARCHProcess:
    program: str
    args: List[str]
    process: asyncio.subprocess.Process
    useSleepRead: bool
    logFile: BufferedWriter
    autoLog: bool

    def __init__(
        self,
        program: str,
        *args: str,
        useSleepRead=False,
        enableLogging=True,
        autoLog=True,
        logCallback=None,
    ):
        """
        Create a new process object.

        Args:
            program: The program to run
            args: The arguments to pass to the program
            useSleepRead: If true, the process will be read using sleep instead of asyncio.subprocess.PIPE. This is useful
                for processes that flush constantly with no buffer.
            enableLogging: If True, the process will log to a file named `<program>.log` on every `get_next_line` call.
                If a string, the process will log to a file with that name.
            autoLog: If true, this will automatically write to the log file. If false, you will have to call `get_next_line` to implicitly write to the log file.
        """
        self.program = program
        self.args = args
        self.useSleepRead = useSleepRead
        self.autoLog = autoLog
        self.logCallback = logCallback

        if enableLogging:
            fileName = enableLogging if type(enableLogging) is str else program + ".log"
            self.logFile = open(fileName, "wb")
        else:
            self.logFile = None

    def __del__(self):
        """
        Stops the process if it is still running and closes the file handles.
        """
        if self.process is not None and self.process.returncode is None:
            self.stop()

        if self.logFile is not None:
            self.logFile.close()

    async def start(self):
        """
        Spawns the process.
        """

        print("Starting", self.program, *self.args)

        self.process = await asyncio.subprocess.create_subprocess_exec(
            self.program, *self.args, stdout=asyncio.subprocess.PIPE
        )

        if self.autoLog and self.logFile is not None:
            asyncio.ensure_future(self.wait())

        return self

    async def start_and_wait(self):
        """
        Spawns the process and waits for it to complete.
        """
        self.autoLog = False
        await self.start()
        await self.wait()

    def stop(self):
        """
        Stops the process.
        """
        self.process.terminate()

    async def is_terminated(self):
        """
        Returns True if the process has terminated.
        """
        if self.process.stdout.at_eof() and not self.useSleepRead:
            return True

        if self.useSleepRead:
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self.process.wait(), 1e-6)
                return True

        return False

    async def get_next_line(self) -> str:
        """
        Gets the next line from the process
        """
        line = await self.process.stdout.readline()

        if self.logCallback:
            line = self.logCallback(line.decode("utf-8")).encode("utf-8")

        if self.useSleepRead:
            await asyncio.sleep(0.01)

        if self.logFile is not None:
            self.logFile.write(line)
            self.logFile.flush()
        else:
            print(line)

        return line

    async def waitForString(self, pattern: str):
        """
        Waits for a string to appear in the process output.
        """
        while True:
            line = (await self.get_next_line()).decode("utf-8")

            if pattern in line:
                break

            if await self.is_terminated():
                break

    async def wait(self):
        """
        Waits and calls `get_next_line` until complete.
        """
        while True:
            await self.get_next_line()

            if await self.is_terminated():
                break
