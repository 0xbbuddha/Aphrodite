from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class HostnameArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class HostnameCommand(CommandBase):
    cmd = "hostname"
    needs_admin = False
    help_cmd = "hostname"
    description = "Get the system hostname"
    version = 1
    author = "@0xbbuddha"
    argument_class = HostnameArguments
    attackmapping = ["T1082"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Linux, SupportedOS.Windows])

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass
