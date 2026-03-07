from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class DrivesArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class DrivesCommand(CommandBase):
    cmd = "drives"
    needs_admin = False
    help_cmd = "drives"
    description = "List drives / mount points"
    version = 1
    author = "@0xbbuddha"
    argument_class = DrivesArguments
    attackmapping = ["T1082"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Linux, SupportedOS.Windows])

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass
