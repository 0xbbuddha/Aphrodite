from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class JobsArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class JobsCommand(CommandBase):
    cmd = "jobs"
    needs_admin = False
    help_cmd = "jobs"
    description = "List active background/interactive jobs"
    version = 1
    author = "@0xbbuddha"
    argument_class = JobsArguments
    attackmapping = []
    attributes = CommandAttributes(supported_os=[SupportedOS.Linux, SupportedOS.Windows])
    browser_script = BrowserScript(script_name="jobs", author="@0xbbuddha")

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass
