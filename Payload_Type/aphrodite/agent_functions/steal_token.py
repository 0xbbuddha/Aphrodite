from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class StealTokenArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="pid",
                type=ParameterType.Number,
                description="PID du processus dont on vole le token",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="Default", ui_position=0, required=True)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == '{':
            self.load_args_from_json_string(self.command_line)
        else:
            parts = self.command_line.strip().split()
            if parts:
                self.add_arg("pid", int(parts[0]))


class StealTokenCommand(CommandBase):
    cmd = "steal_token"
    needs_admin = False
    help_cmd = "steal_token <pid>"
    description = (
        "Vole le token d'acces d'un processus et impersonne l'utilisateur associe. "
        "Active SeDebugPrivilege automatiquement. "
        "Utiliser rev2self pour revenir au token original."
    )
    version = 1
    author = "@0xbbuddha"
    argument_class = StealTokenArguments
    attackmapping = ["T1134.001"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Windows])

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        pid = taskData.args.get_arg("pid")
        response.DisplayParams = f"pid={pid}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        pass
