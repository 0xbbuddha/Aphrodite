from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class WgetArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="url",
                type=ParameterType.String,
                description="URL to download",
                parameter_group_info=[ParameterGroupInfo(group_name="Default", ui_position=0, required=True)],
            ),
            CommandParameter(
                name="output",
                type=ParameterType.String,
                description="Local path to save the file (default: filename from URL)",
                parameter_group_info=[ParameterGroupInfo(group_name="Default", ui_position=1, required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("url", self.command_line.strip())


class WgetCommand(CommandBase):
    cmd = "wget"
    needs_admin = False
    help_cmd = "wget <url> [output]"
    description = "Download a file from a URL to the target system"
    version = 1
    author = "@0xbbuddha"
    argument_class = WgetArguments
    attackmapping = ["T1105"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Linux, SupportedOS.Windows])

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        url = taskData.args.get_arg("url")
        output = taskData.args.get_arg("output") or ""
        response.DisplayParams = url + (f" -> {output}" if output else "")
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        pass
