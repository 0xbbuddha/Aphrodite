from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class RunasArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="command",
                type=ParameterType.String,
                description="Command to run",
                parameter_group_info=[ParameterGroupInfo(group_name="Default", ui_position=0, required=True)],
            ),
            CommandParameter(
                name="user",
                type=ParameterType.String,
                description="Username to run as",
                parameter_group_info=[ParameterGroupInfo(group_name="Default", ui_position=1, required=True)],
            ),
            CommandParameter(
                name="password",
                type=ParameterType.String,
                description="Password for the user",
                parameter_group_info=[ParameterGroupInfo(group_name="Default", ui_position=2, required=True)],
            ),
            CommandParameter(
                name="domain",
                type=ParameterType.String,
                description="Domain (Windows only, default: .)",
                parameter_group_info=[ParameterGroupInfo(group_name="Default", ui_position=3, required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == '{':
            self.load_args_from_json_string(self.command_line)


class RunasCommand(CommandBase):
    cmd = "runas"
    needs_admin = False
    help_cmd = "runas <command> <user> <password> [domain]"
    description = "Run a command as another user (Windows: PSCredential / Linux: su -c)"
    version = 1
    author = "@0xbbuddha"
    argument_class = RunasArguments
    attackmapping = ["T1134.002"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Linux, SupportedOS.Windows])

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        user = taskData.args.get_arg("user")
        command = taskData.args.get_arg("command")
        response.DisplayParams = f"{user}: {command}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        pass
