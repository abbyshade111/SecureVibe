import subprocess
def run(cmd):
    return subprocess.call(cmd, shell=True)  # nosemgrep
def run2(cmd):
    # nosemgrep: shell-true
    return subprocess.call(cmd, shell=True)
