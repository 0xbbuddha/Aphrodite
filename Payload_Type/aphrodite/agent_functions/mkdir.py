from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class MkdirArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="path",
                type=ParameterType.String,
                description="Directory path to create",
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
                self.add_arg("path", self.command_line)


class MkdirCommand(CommandBase):
    cmd = "mkdir"
    needs_admin = False
    help_cmd = "mkdir <path>"
    description = "Create a directory"
    version = 1
    author = "@0xbbuddha"
    argument_class = MkdirArguments
    attackmapping = ["T1106"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Linux, SupportedOS.Windows])

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = task.args.get_arg("path")
        return task

    async def process_response(self, response: AgentResponse):
        pass
