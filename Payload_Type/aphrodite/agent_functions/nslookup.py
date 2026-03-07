from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class NslookupArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="host",
                type=ParameterType.String,
                description="Hostname or IP to resolve",
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
                self.add_arg("host", self.command_line.strip())


class NslookupCommand(CommandBase):
    cmd = "nslookup"
    needs_admin = False
    help_cmd = "nslookup <host>"
    description = "Resolve a hostname via DNS"
    version = 1
    author = "@0xbbuddha"
    argument_class = NslookupArguments
    attackmapping = ["T1018"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Linux, SupportedOS.Windows])

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = task.args.get_arg("host")
        return task

    async def process_response(self, response: AgentResponse):
        pass
