"""Warden's governance layer — the deterministic security core.

HARD RULE: no code in this package may call an LLM. Authorization decisions are
made here by ordinary Python, so that no amount of persuasive (possibly injected)
text can influence them. If you ever feel tempted to "ask the model whether this
is allowed," that instinct is the vulnerability this whole project exists to fix.
"""
