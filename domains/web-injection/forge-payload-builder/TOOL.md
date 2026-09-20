# Forge — local deterministic payload forger

Offline payload assembler (no AI, no network). YAML templates + bypass pipeline + requires filters.

## Run
```bash
cd domains/web-injection/forge-payload-builder
pip install pyyaml   # only dep
./forge.sh           # TUI
./forge-gui.sh       # GUI (tkinter)
```

## API
```python
from forge import engine
rules = engine.load_rules("data")
res = engine.generate(rules, engine.make_state(
    vuln="sqli", component="mysql", template="sqli.mysql.union.basic",
    slots={"close": "'", "cols": "3", "pos": "2"},
    bypasses=["bypass.case.alternate"], outputs=["raw", "curl"],
))
print(res["payload"])
```

## Placement
Tool under `web-injection/forge-payload-builder/` — NOT a methodology router.
