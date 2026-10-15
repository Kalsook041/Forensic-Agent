"""Private trusted launch gate; never registered as a model tool.

The parent assigns this waiting process to its Job before sending any payload.
Windows then assigns its child to the same Job atomically during creation.
"""
import base64
import json
import subprocess
import sys


def main():
    payload = sys.stdin.buffer.read(16 * 1024**2 + 1)
    if not payload or len(payload) > 16 * 1024**2:
        return 125
    request = json.loads(payload)
    argv = request["argv"]
    if not isinstance(argv, list) or not argv or not all(isinstance(x, str) for x in argv):
        return 125
    data = base64.b64decode(request["input"], validate=True)
    # stdout/stderr inherit the parent's capture pipes without a second drain.
    child = subprocess.Popen(argv, shell=False, stdin=subprocess.PIPE)
    child.communicate(input=data)
    return child.returncode


if __name__ == "__main__":
    sys.exit(main())
