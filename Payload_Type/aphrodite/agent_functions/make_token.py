from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class MakeTokenArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="username",
                type=ParameterType.String,
                description="Nom d'utilisateur",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="Default", ui_position=0, required=True)],
            ),
            CommandParameter(
                name="domain",
                type=ParameterType.String,
                description="Domaine (. pour local)",
                default_value=".",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="Default", ui_position=1, required=False)],
            ),
            CommandParameter(
                name="password",
                type=ParameterType.String,
                description="Mot de passe",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="Default", ui_position=2, required=True)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == '{':
            self.load_args_from_json_string(self.command_line)


class MakeTokenCommand(CommandBase):
    cmd = "make_token"
    needs_admin = False
    help_cmd = "make_token -username <user> -domain <domain> -password <pass>"
    description = (
        "Cree un token Windows avec des identifiants (LogonUser LOGON_NEWCREDENTIALS) "
        "et impersonne cet utilisateur pour les operations reseau. "
        "Utiliser rev2self pour revenir au token original."
    )
    version = 1
    author = "@0xbbuddha"
    argument_class = MakeTokenArguments
    attackmapping = ["T1134.003"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Windows])

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        user   = taskData.args.get_arg("username") or ""
        domain = taskData.args.get_arg("domain") or "."
        response.DisplayParams = f"{domain}\\{user}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        pass
