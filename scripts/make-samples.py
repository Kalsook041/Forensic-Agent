from pathlib import Path
import sys

from forensic_agent.samples import create_samples

target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1] / "examples" / "检材"
create_samples(target)
print(str(target.resolve()))
