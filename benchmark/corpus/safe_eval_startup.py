import os
# SAFE: executes the *developer's own* PYTHONSTARTUP script (local env only).
# Input source is NOT attacker-controlled; not remotely triggerable.
# Taint analysis: source = local environment -> sink = eval. No remote taint.
startup = os.environ.get("PYTHONSTARTUP")
if startup and os.path.isfile(startup):
    with open(startup) as f:
        eval(compile(f.read(), startup, "exec"), {})
