from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class GetenvArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="name",
                type=ParameterType.String,
                description="Environment variable name",
                parameter_group_info=[
                    ParameterGroupInfo(group_name="Default", ui_position=0, required=True)
                ],
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line.strip()[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("name", self.command_line.strip())


class GetenvCommand(CommandBase):
    cmd = "getenv"
    needs_admin = False
    help_cmd = "getenv <name>"
    description = "Get the value of an environment variable"
    version = 1
    author = "@0xbbuddha"
    argument_class = GetenvArguments
    attackmapping = ["T1082"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Linux, SupportedOS.Windows])

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = task.args.get_arg("name")
        return task

    async def process_response(self, response: AgentResponse):
        pass
