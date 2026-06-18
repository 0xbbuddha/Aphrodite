from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class NetstatArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class NetstatCommand(CommandBase):
    cmd = "netstat"
    needs_admin = False
    help_cmd = "netstat"
    description = "Display active network connections and listening ports"
    version = 1
    author = "@0xbbuddha"
    argument_class = NetstatArguments
    attackmapping = ["T1049"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Linux, SupportedOS.Windows])
    browser_script = BrowserScript(script_name="netstat", author="@0xbbuddha")

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass
