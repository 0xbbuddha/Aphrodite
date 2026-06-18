from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class Rev2SelfArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class Rev2SelfCommand(CommandBase):
    cmd = "rev2self"
    needs_admin = False
    help_cmd = "rev2self"
    description = (
        "Abandonne l'impersonation en cours (RevertToSelf) et ferme le token duplique. "
        "A utiliser apres steal_token ou make_token."
    )
    version = 1
    author = "@0xbbuddha"
    argument_class = Rev2SelfArguments
    attackmapping = ["T1134"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Windows])

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        response.DisplayParams = ""
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        pass
