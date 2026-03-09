from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class CurlArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="url",
                type=ParameterType.String,
                description="URL to request",
                parameter_group_info=[ParameterGroupInfo(group_name="Default", ui_position=0, required=True)],
            ),
            CommandParameter(
                name="method",
                type=ParameterType.String,
                description="HTTP method (default: GET)",
                parameter_group_info=[ParameterGroupInfo(group_name="Default", ui_position=1, required=False)],
            ),
            CommandParameter(
                name="data",
                type=ParameterType.String,
                description="Request body",
                parameter_group_info=[ParameterGroupInfo(group_name="Default", ui_position=2, required=False)],
            ),
            CommandParameter(
                name="headers",
                type=ParameterType.String,
                description="Extra headers, one per line (Key: Value)",
                parameter_group_info=[ParameterGroupInfo(group_name="Default", ui_position=3, required=False)],
            ),
            CommandParameter(
                name="output",
                type=ParameterType.String,
                description="Save response body to this local path (optional)",
                parameter_group_info=[ParameterGroupInfo(group_name="Default", ui_position=4, required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                # Handle "METHOD URL" or just "URL"
                parts = self.command_line.strip().split(None, 1)
                http_methods = {"GET", "POST", "PUT", "DELETE", "HEAD", "PATCH", "OPTIONS"}
                if len(parts) == 2 and parts[0].upper() in http_methods:
                    self.add_arg("method", parts[0].upper())
                    self.add_arg("url", parts[1])
                else:
                    self.add_arg("url", self.command_line.strip())


class CurlCommand(CommandBase):
    cmd = "curl"
    needs_admin = False
    help_cmd = "curl <url> [-X method] [-d data] [-H headers] [-o output]"
    description = "Perform an HTTP request from the target system"
    version = 1
    author = "@0xbbuddha"
    argument_class = CurlArguments
    attackmapping = ["T1105", "T1071.001"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Linux, SupportedOS.Windows])

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        url = taskData.args.get_arg("url")
        method = taskData.args.get_arg("method") or "GET"
        response.DisplayParams = f"{method.upper()} {url}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        pass
