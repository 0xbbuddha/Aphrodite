from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class EnvArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class EnvCommand(CommandBase):
    cmd = "env"
    needs_admin = False
    help_cmd = "env"
    description = "List all environment variables"
    version = 1
    author = "@0xbbuddha"
    argument_class = EnvArguments
    attackmapping = ["T1082"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Linux, SupportedOS.Windows])

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass
