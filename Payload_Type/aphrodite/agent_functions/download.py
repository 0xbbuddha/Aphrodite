from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class DownloadArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="path",
                type=ParameterType.String,
                description="Path of the file to download from the target",
                parameter_group_info=[
                    ParameterGroupInfo(group_name="Default", ui_position=0, required=True)
                ],
            )
        ]

    async def parse_arguments(self):
        if self.command_line.startswith("{"):
            import json
            d = json.loads(self.command_line)
            self.add_arg("path", d.get("path", ""))
        elif len(self.command_line) > 0:
            self.add_arg("path", self.command_line.strip())


class DownloadCommand(CommandBase):
    cmd = "download"
    needs_admin = False
    help_cmd = "download <path>"
    description = "Download a file from the target to Mythic"
    version = 1
    author = "@0xbbuddha"
    argument_class = DownloadArguments
    attackmapping = ["T1020", "T1030", "T1041"]
    supported_ui_features = ["file_browser:download"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Linux, SupportedOS.Windows])

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = task.args.get_arg("path")
        return task

    async def process_response(self, response: AgentResponse):
        pass
