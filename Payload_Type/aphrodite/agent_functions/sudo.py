from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class SudoArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="command",
                type=ParameterType.String,
                description="Command to run with elevated privileges",
                parameter_group_info=[ParameterGroupInfo(group_name="Default", ui_position=0, required=True)],
            ),
            CommandParameter(
                name="user",
                type=ParameterType.String,
                description="User to run as (default: root)",
                parameter_group_info=[ParameterGroupInfo(group_name="Default", ui_position=1, required=False)],
            ),
            CommandParameter(
                name="password",
                type=ParameterType.String,
                description="Password for sudo (leave empty if passwordless sudo)",
                parameter_group_info=[ParameterGroupInfo(group_name="Default", ui_position=2, required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("command", self.command_line)


class SudoCommand(CommandBase):
    cmd = "sudo"
    needs_admin = False
    help_cmd = "sudo <command> [user] [password]"
    description = "Run a command as another user via sudo (Linux only)"
    version = 1
    author = "@0xbbuddha"
    argument_class = SudoArguments
    attackmapping = ["T1548.003"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Linux])

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        user = taskData.args.get_arg("user") or "root"
        command = taskData.args.get_arg("command")
        response.DisplayParams = f"-u {user} {command}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        pass
