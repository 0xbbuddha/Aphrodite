from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class ScreenshotArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class ScreenshotCommand(CommandBase):
    cmd = "screenshot"
    needs_admin = False
    help_cmd = "screenshot"
    description = (
        "Capture the current desktop via GDI BitBlt and send it to Mythic. "
        "The image appears in the Screenshots tab."
    )
    version = 1
    author = "@0xbbuddha"
    argument_class = ScreenshotArguments
    attackmapping = ["T1113"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        supported_ui_features=["task_response:screenshot"],
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass
