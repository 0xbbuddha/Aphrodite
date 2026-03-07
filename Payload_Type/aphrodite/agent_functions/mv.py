from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class MvArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="source",
                type=ParameterType.String,
                description="Source path",
                parameter_group_info=[
                    ParameterGroupInfo(group_name="Default", ui_position=0, required=True)
                ],
            ),
            CommandParameter(
                name="destination",
                type=ParameterType.String,
                description="Destination path",
                parameter_group_info=[
                    ParameterGroupInfo(group_name="Default", ui_position=1, required=True)
                ],
            ),
        ]

    async def parse_arguments(self):
        if self.command_line.startswith("{"):
            import json
            d = json.loads(self.command_line)
            self.add_arg("source", d.get("source", ""))
            self.add_arg("destination", d.get("destination", ""))
        else:
            parts = self.command_line.split(None, 1)
            if len(parts) == 2:
                self.add_arg("source", parts[0])
                self.add_arg("destination", parts[1])


class MvCommand(CommandBase):
    cmd = "mv"
    needs_admin = False
    help_cmd = "mv <source> <destination>"
    description = "Move or rename a file"
    version = 1
    author = "@0xbbuddha"
    argument_class = MvArguments
    attackmapping = ["T1074"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Linux, SupportedOS.Windows])

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = "{} -> {}".format(
            task.args.get_arg("source"), task.args.get_arg("destination")
        )
        return task

    async def process_response(self, response: AgentResponse):
        pass
