"""Explainable, offline analysis of saved email messages (.eml).

Nothing in this package renders HTML, follows a link, opens an attachment or sends anything
off the machine.
"""

from .analyze import analyze, analyze_stream

__all__ = ["analyze", "analyze_stream"]
