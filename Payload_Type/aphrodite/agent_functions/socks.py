from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class SocksArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="port",
                cli_name="port",
                display_name="Port",
                type=ParameterType.Number,
                description="Port on the Mythic server to open for SOCKS5",
                parameter_group_info=[
                    ParameterGroupInfo(group_name="Default", ui_position=0, required=True)
                ],
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Must specify a port number.")
        try:
            self.load_args_from_json_string(self.command_line)
        except Exception:
            port = self.command_line.strip()
            try:
                self.add_arg("port", int(port))
            except Exception:
                raise Exception("Invalid port number: {}".format(port))


class SocksCommand(CommandBase):
    cmd = "socks"
    needs_admin = False
    help_cmd = "socks <port>"
    description = "Start a SOCKS5 proxy through this agent"
    version = 1
    author = "@0xbbuddha"
    argument_class = SocksArguments
    attackmapping = ["T1090"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Linux, SupportedOS.Windows])

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        port = taskData.args.get_arg("port")
        resp = await SendMythicRPCProxyStartCommand(MythicRPCProxyStartMessage(
            TaskID=taskData.Task.ID,
            PortType="socks",
            LocalPort=port,
        ))
        if not resp.Success:
            response.TaskStatus = MythicStatus.Error
            response.Stderr = resp.Error
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=taskData.Task.ID,
                Response=resp.Error.encode(),
            ))
        else:
            response.DisplayParams = "SOCKS5 on port {}".format(port)
            response.TaskStatus = MythicStatus.Success
            response.Completed = True
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        pass
