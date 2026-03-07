from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class UploadArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="remote_path",
                type=ParameterType.String,
                description="Destination path on the target",
                parameter_group_info=[
                    ParameterGroupInfo(group_name="Default", ui_position=0, required=True)
                ],
            ),
            CommandParameter(
                name="file",
                type=ParameterType.File,
                description="File to upload",
                parameter_group_info=[
                    ParameterGroupInfo(group_name="Default", ui_position=1, required=True)
                ],
            ),
        ]

    async def parse_arguments(self):
        if self.command_line.startswith("{"):
            import json
            d = json.loads(self.command_line)
            self.add_arg("remote_path", d.get("remote_path", ""))
            if "file" in d:
                self.add_arg("file_id", d["file"])


class UploadCommand(CommandBase):
    cmd = "upload"
    needs_admin = False
    help_cmd = "upload"
    description = "Upload a file from Mythic to the target"
    version = 1
    author = "@0xbbuddha"
    argument_class = UploadArguments
    attackmapping = ["T1105"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Linux, SupportedOS.Windows])

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        ## Pass the Mythic file_id to the agent as the "file_id" parameter
        file_id = task.args.get_arg("file")
        task.args.add_arg("file_id", file_id)
        task.display_params = "-> " + task.args.get_arg("remote_path")
        return task

    async def process_response(self, response: AgentResponse):
        pass
