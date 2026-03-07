from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class PshArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="shell",
                cli_name="shell",
                display_name="Shell executable",
                type=ParameterType.String,
                description="Path to the shell to spawn (default: $SHELL on Linux, cmd.exe on Windows)",
                default_value="",
                parameter_group_info=[
                    ParameterGroupInfo(group_name="Default", ui_position=0, required=False)
                ],
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line.strip()) > 0:
            if self.command_line.strip()[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("shell", self.command_line.strip())


class PshCommand(CommandBase):
    cmd = "psh"
    needs_admin = False
    help_cmd = "psh [shell]"
    description = "Spawn a persistent interactive shell session"
    version = 1
    author = "@0xbbuddha"
    argument_class = PshArguments
    attackmapping = ["T1059", "T1059.004"]
    supported_ui_features = ["task_response:interactive"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Linux, SupportedOS.Windows])

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        shell = taskData.args.get_arg("shell")
        response.DisplayParams = shell if shell else "(default shell)"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        pass
