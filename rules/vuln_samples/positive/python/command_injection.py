# POSITIVE: Command injection — should trigger py-command-injection
import os
import subprocess
from flask import request

def run_command():
    user_input = request.args.get('cmd')
    
    # Unsafe: f-string in os.system
    os.system(f"ls {user_input}")
    # Unsafe: concatenation in subprocess
    subprocess.call("ping " + user_input, shell=True)
    # Unsafe: popen
    os.popen(f"cat {user_input}")
