from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class KillArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="pid",
                type=ParameterType.String,
                description="PID of the process to kill",
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
                self.add_arg("pid", self.command_line.strip())


class KillCommand(CommandBase):
    cmd = "kill"
    needs_admin = False
    help_cmd = "kill <pid>"
    description = "Kill a process by PID"
    version = 1
    author = "@0xbbuddha"
    argument_class = KillArguments
    attackmapping = ["T1489"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Linux, SupportedOS.Windows])

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = "PID " + task.args.get_arg("pid")
        return task

    async def process_response(self, response: AgentResponse):
        pass
