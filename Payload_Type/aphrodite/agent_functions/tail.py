from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class TailArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="path",
                type=ParameterType.String,
                description="File path to tail",
                parameter_group_info=[
                    ParameterGroupInfo(group_name="Default", ui_position=0, required=True)
                ],
            ),
            CommandParameter(
                name="lines",
                type=ParameterType.String,
                description="Number of lines to show (default: 10)",
                default_value="10",
                parameter_group_info=[
                    ParameterGroupInfo(group_name="Default", ui_position=1, required=False)
                ],
            ),
        ]

    async def parse_arguments(self):
        if self.command_line.startswith("{"):
            import json
            d = json.loads(self.command_line)
            self.add_arg("path", d.get("path", ""))
            self.add_arg("lines", str(d.get("lines", "10")))
        else:
            parts = self.command_line.split()
            if len(parts) >= 1:
                self.add_arg("path", parts[0])
            if len(parts) >= 2:
                self.add_arg("lines", parts[1])


class TailCommand(CommandBase):
    cmd = "tail"
    needs_admin = False
    help_cmd = "tail <path> [lines]"
    description = "Display the last N lines of a file"
    version = 1
    author = "@0xbbuddha"
    argument_class = TailArguments
    attackmapping = ["T1083"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Linux, SupportedOS.Windows])

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = "-{} {}".format(
            task.args.get_arg("lines"), task.args.get_arg("path")
        )
        return task

    async def process_response(self, response: AgentResponse):
        pass
