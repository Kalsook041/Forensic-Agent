import base64
import json
import sys

from .cli import main

arguments = sys.argv[1:]
if len(arguments) == 2 and arguments[0] == "--encoded-argv":
    arguments = json.loads(base64.b64decode(arguments[1], validate=True).decode("utf-8"))
    if not isinstance(arguments, list) or any(not isinstance(item, str) for item in arguments):
        raise SystemExit("Invalid encoded CLI arguments")
raise SystemExit(main(arguments))
