from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from mythic_container.PayloadBuilder import *


class SleepArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="interval",
                type=ParameterType.Number,
                description="Sleep interval in seconds",
                parameter_group_info=[ParameterGroupInfo(group_name="Default", ui_position=0, required=True)],
            ),
            CommandParameter(
                name="jitter",
                type=ParameterType.Number,
                description="Jitter percentage (0-100)",
                default_value=0,
                parameter_group_info=[ParameterGroupInfo(group_name="Default", ui_position=1, required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise ValueError("Interval required")
        if self.command_line.strip()[0] == '{':
            self.load_args_from_json_string(self.command_line)
        else:
            parts = self.command_line.strip().split()
            self.add_arg("interval", int(parts[0]))
            if len(parts) > 1:
                self.add_arg("jitter", int(parts[1]))
            else:
                self.add_arg("jitter", 0)


class SleepCommand(CommandBase):
    cmd = "sleep"
    needs_admin = False
    help_cmd = "sleep <seconds> [jitter%]"
    description = "Set callback sleep interval and optional jitter percentage"
    version = 1
    author = "@0xbbuddha"
    argument_class = SleepArguments
    attackmapping = ["T1029"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Linux, SupportedOS.Windows])

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        interval = task.args.get_arg("interval")
        jitter = task.args.get_arg("jitter")
        task.display_params = f"{interval}s jitter={jitter}%"
        return task

    async def process_response(self, response: AgentResponse):
        pass
