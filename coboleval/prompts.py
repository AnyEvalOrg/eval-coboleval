"""Exact upstream chat prompt; no grading fields enter model messages."""
OPENAI_SYSTEM_PROMPT = """```
{}
```

Complete the above program. It should consist of a single markdown code block following on from the lines above until the end of the program. It should terminate with `GOBACK`."""

def system_prompt(record: dict) -> str:
    return OPENAI_SYSTEM_PROMPT.format(record["prompt"])
