#!/usr/bin/env python3
import mythic_container
from agent_functions import builder

# --- Original commands ---
from agent_functions import shell
from agent_functions import ls
from agent_functions import pwd
from agent_functions import whoami
from agent_functions import cd
from agent_functions import cat
from agent_functions import sleep_cmd
from agent_functions import exit_cmd

# --- New commands ---
from agent_functions import mkdir
from agent_functions import rm
from agent_functions import mv
from agent_functions import cp
from agent_functions import env
from agent_functions import hostname
from agent_functions import ps
from agent_functions import kill
from agent_functions import tail
from agent_functions import echo
from agent_functions import drives
from agent_functions import ifconfig
from agent_functions import arp
from agent_functions import nslookup
from agent_functions import uptime
from agent_functions import getenv
from agent_functions import setenv
from agent_functions import download
from agent_functions import upload

# --- Interactive / proxy ---
from agent_functions import psh
from agent_functions import socks

mythic_container.mythic_service.start_and_run_forever()
