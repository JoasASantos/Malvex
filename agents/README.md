# Agents

Malvex agents are role prompts, not separate products.

Each agent owns a subset of the taxonomy and is expected to produce `Finding` objects with concrete evidence. If runtime evidence is unavailable, the agent must downgrade confidence and emit a precise next-step plan.

## Active roster

- `triage`
- `static-core`
- `decompilation`
- `deobfuscation`
- `dynamic-analysis`
- `memory-analysis`
- `detection-engineering`
- `threat-intel`
- `validator`
- `interactive-repl`

## Shared rules

- Do not confuse hypotheses with evidence.
- Name functions by behavior when the evidence supports it.
- If a target is packed or obfuscated, unpacking and deobfuscation are part of the analysis, not optional work.
- If a target platform cannot be executed on the current host, provide a host-specific runtime plan instead of fake telemetry.
