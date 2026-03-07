from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class SetenvArguments(TaskArguments):
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
            ),
            CommandParameter(
                name="value",
                type=ParameterType.String,
                description="Value to set",
                parameter_group_info=[
                    ParameterGroupInfo(group_name="Default", ui_position=1, required=True)
                ],
            ),
        ]

    async def parse_arguments(self):
        if self.command_line.startswith("{"):
            import json
            d = json.loads(self.command_line)
            self.add_arg("name", d.get("name", ""))
            self.add_arg("value", d.get("value", ""))
        else:
            parts = self.command_line.split(None, 1)
            if len(parts) >= 1:
                self.add_arg("name", parts[0])
            if len(parts) >= 2:
                self.add_arg("value", parts[1])


class SetenvCommand(CommandBase):
    cmd = "setenv"
    needs_admin = False
    help_cmd = "setenv <name> <value>"
    description = "Set an environment variable"
    version = 1
    author = "@0xbbuddha"
    argument_class = SetenvArguments
    attackmapping = []
    attributes = CommandAttributes(supported_os=[SupportedOS.Linux, SupportedOS.Windows])

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = "{}={}".format(
            task.args.get_arg("name"), task.args.get_arg("value")
        )
        return task

    async def process_response(self, response: AgentResponse):
        pass
