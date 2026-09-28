"""Shared command runner and optional external-tool integrations.

Concrete adapters are imported from their modules to avoid eager loading of
application scope dependencies while the package is initializing.
"""
