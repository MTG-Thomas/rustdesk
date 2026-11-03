"""Keep standalone qualification and the opt-in desktop verifier identical."""

from pathlib import Path
import tomllib

root = Path(__file__).resolve().parents[1]
canonical = root / "libs/base/quick_support_guard"
desktop = root / "libs/quick_support_desktop_guard"
guard = tomllib.loads((canonical / "Cargo.toml").read_text())
adapter = tomllib.loads((desktop / "Cargo.toml").read_text())
application = tomllib.loads((root / "Cargo.toml").read_text())

assert guard["dependencies"] == adapter["dependencies"], "verifier dependency drift"
assert guard["package"] == adapter["package"], "verifier package contract drift"
assert (desktop / adapter["lib"]["path"]).resolve() == canonical / "src/lib.rs"
dependency = application["dependencies"]["quick_support_guard"]
assert dependency["optional"] is True
assert (root / dependency["path"]).resolve() == desktop
assert application["features"]["quick-support-child"] == [
    "dep:quick_support_guard", "hbb_common/quick-support-profile"
]
shared = tomllib.loads((root / "libs/hbb_common/Cargo.toml").read_text())
assert shared["features"]["quick-support-profile"] == []
assert "quick-support-profile" not in shared["features"]["default"]
assert "quick-support-child" not in application["features"]["default"]
print("Desktop links the canonical verifier source and dependency contract, opt-in only.")
