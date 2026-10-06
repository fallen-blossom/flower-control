"""Fixed Claude Code Hook entrypoint; host identity is not a model argument."""
from pre_tool_use import main

if __name__ == "__main__":
    raise SystemExit(main(host="claude-code"))
