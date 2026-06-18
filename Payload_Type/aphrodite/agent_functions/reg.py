from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class RegArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action",
                type=ParameterType.ChooseOne,
                choices=["query", "add", "delete", "enum"],
                default_value="query",
                description="Registry operation",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="Default", ui_position=0, required=True)],
            ),
            CommandParameter(
                name="key",
                type=ParameterType.String,
                description=r"Full registry key path (e.g. HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion)",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="Default", ui_position=1, required=True)],
            ),
            CommandParameter(
                name="value",
                type=ParameterType.String,
                description="Value name (for query/add/delete value; omit to delete an entire key)",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="Default", ui_position=2, required=False)],
            ),
            CommandParameter(
                name="data",
                type=ParameterType.String,
                description="Data to write (for add; REG_BINARY expects base64-encoded bytes)",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="Default", ui_position=3, required=False)],
            ),
            CommandParameter(
                name="type",
                type=ParameterType.ChooseOne,
                choices=["REG_SZ", "REG_DWORD", "REG_BINARY", "REG_EXPAND_SZ"],
                default_value="REG_SZ",
                description="Value type (for add only)",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="Default", ui_position=4, required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == '{':
            self.load_args_from_json_string(self.command_line)


class RegCommand(CommandBase):
    cmd = "reg"
    needs_admin = False
    help_cmd = (
        r"reg -action query  -key HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion -value ProductName" + "\n"
        r"reg -action enum   -key HKCU\SOFTWARE" + "\n"
        r"reg -action add    -key HKCU\SOFTWARE\Test -value Hello -data World -type REG_SZ" + "\n"
        r"reg -action delete -key HKCU\SOFTWARE\Test -value Hello"
    )
    description = "Read, write, enumerate and delete Windows registry keys and values."
    version = 1
    author = "@0xbbuddha"
    argument_class = RegArguments
    attackmapping = ["T1012", "T1112"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Windows])
    browser_script = BrowserScript(script_name="reg", author="@0xbbuddha")

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        action = taskData.args.get_arg("action") or "query"
        key    = taskData.args.get_arg("key")    or ""
        value  = taskData.args.get_arg("value")  or ""

        if value:
            response.DisplayParams = f"{action} {key}\\{value}"
        else:
            response.DisplayParams = f"{action} {key}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        pass
