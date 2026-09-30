"""Adapters that put Warden's gate in front of other agent frameworks.

Each adapter lives behind an optional extra (e.g. `pip install -e ".[agentdojo]"`)
and is imported explicitly; importing `warden` never pulls these dependencies in.
"""
