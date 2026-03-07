from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class EchoArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="text",
                type=ParameterType.String,
                description="Text to echo back",
                parameter_group_info=[
                    ParameterGroupInfo(group_name="Default", ui_position=0, required=True)
                ],
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("text", self.command_line)


class EchoCommand(CommandBase):
    cmd = "echo"
    needs_admin = False
    help_cmd = "echo <text>"
    description = "Echo text back"
    version = 1
    author = "@0xbbuddha"
    argument_class = EchoArguments
    attackmapping = []
    attributes = CommandAttributes(supported_os=[SupportedOS.Linux, SupportedOS.Windows])

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = task.args.get_arg("text")
        return task

    async def process_response(self, response: AgentResponse):
        pass
