from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from mythic_container.PayloadBuilder import *


class ShellArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="command",
                type=ParameterType.String,
                description="Shell command to execute",
                parameter_group_info=[ParameterGroupInfo(group_name="Default", ui_position=0, required=True)],
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise ValueError("Command required")
        if self.command_line[0] == '{':
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("command", self.command_line)


class ShellCommand(CommandBase):
    cmd = "shell"
    needs_admin = False
    help_cmd = "shell <command>"
    description = "Execute a shell command via /bin/sh"
    version = 1
    author = "@0xbbuddha"
    argument_class = ShellArguments
    attackmapping = ["T1059.004"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Linux, SupportedOS.Windows])

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = task.args.get_arg("command")
        return task

    async def process_response(self, response: AgentResponse):
        pass
