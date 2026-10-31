"""sfab: the lab generator for The AI Serving Fabric's companion labs.

One spec (spec/) and one chapter.yaml per lab select a model (sfab.spec.select); renderers turn
the model into the lab's committed files (sfab.render). See FRAMEWORK.md and API.md.
"""

GENERATOR_VERSION = 1

__all__ = ["GENERATOR_VERSION"]
