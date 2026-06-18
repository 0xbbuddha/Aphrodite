import base64
import struct

from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


def pack_bof_args(args_list: list) -> bytes:
    """Pack arguments in Cobalt Strike beacon format:
       each arg = 4-byte LE length + raw bytes.
       types: str, wstr, int, short, bin (base64)
    """
    buf = b""
    for arg in args_list:
        atype = arg.get("type", "str").lower()
        value = arg.get("value", "")
        if atype == "str":
            data = value.encode("utf-8") + b"\x00"
        elif atype == "wstr":
            data = value.encode("utf-16-le") + b"\x00\x00"
        elif atype == "int":
            data = struct.pack("<i", int(value))
        elif atype == "short":
            data = struct.pack("<h", int(value))
        elif atype == "bin":
            data = base64.b64decode(value)
        else:
            data = value.encode("utf-8")
        buf += struct.pack("<i", len(data)) + data
    return buf


class InlineExecuteArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="bof_file",
                type=ParameterType.File,
                description="Fichier BOF/COFF a executer (x64 Windows COFF)",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="Default", ui_position=0, required=True)],
            ),
            CommandParameter(
                name="args",
                type=ParameterType.String,
                description=(
                    'Arguments JSON: [{"type":"str","value":"hello"},{"type":"int","value":42}] '
                    '- types: str, wstr, int, short, bin(base64). Laisser vide si aucun arg.'
                ),
                default_value="[]",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="Default", ui_position=1, required=False)],
            ),
            CommandParameter(
                name="entry_point",
                type=ParameterType.String,
                description="Nom de la fonction d'entree du BOF (defaut: go)",
                default_value="go",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="Default", ui_position=2, required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == '{':
            self.load_args_from_json_string(self.command_line)


class InlineExecuteCommand(CommandBase):
    cmd = "inline_execute"
    needs_admin = False
    help_cmd = "inline_execute -bof_file <file> [-args <json>] [-entry_point go]"
    description = (
        "Execute un fichier BOF/COFF (Beacon Object File) directement en memoire "
        "dans le processus courant. "
        "Implemente un loader COFF x64 avec Beacon API compatible (BeaconOutput, "
        "BeaconPrintf, BeaconDataParse/Extract/Int/Short/Length, BeaconFormatAlloc/Free/Append, "
        "BeaconIsAdmin, BeaconUseToken, BeaconRevertToken, toWideChar). "
        "Supporte les imports externes au format LIBNAME$FuncName."
    )
    version = 1
    author = "@0xbbuddha"
    argument_class = InlineExecuteArguments
    attackmapping = ["T1059.001", "T1620"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Windows])

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        import json as _json
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        try:
            file_id = taskData.args.get_arg("bof_file")
            args_str = taskData.args.get_arg("args") or "[]"
            entry = taskData.args.get_arg("entry_point") or "go"

            file_resp = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(
                AgentFileId=file_id))
            if not file_resp.Success:
                response.Success = False
                response.Error = f"Failed to retrieve BOF file: {file_resp.Error}"
                return response

            bof_b64 = base64.b64encode(file_resp.Content).decode()

            try:
                args_list = _json.loads(args_str)
            except Exception:
                args_list = []

            packed = pack_bof_args(args_list)
            args_b64 = base64.b64encode(packed).decode()

            taskData.args.add_arg("bof_b64",  bof_b64,  parameter_type=ParameterType.String)
            taskData.args.add_arg("args_b64", args_b64, parameter_type=ParameterType.String)

            response.DisplayParams = f"entry={entry} args_len={len(packed)}"
        except Exception as e:
            response.Success = False
            response.Error = str(e)
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        pass
