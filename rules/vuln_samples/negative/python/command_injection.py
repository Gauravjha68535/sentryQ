# NEGATIVE: Safe command execution
import subprocess

def run_safe(user_input):
    # Safe: list form, shell=False
    subprocess.run(['ls', user_input], shell=False)
    subprocess.call(['ping', '-c', '1', user_input], shell=False)
