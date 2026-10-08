"""
Detection package for MAD-PS Unified Cyber Defense Platform.
Includes 6 specialized ML/analytical detection branches, meta-classifier ensemble, and live traffic inspector.
"""

from .classifier import MetaClassifier
from .inspector import LiveTrafficInspector

__all__ = ["MetaClassifier", "LiveTrafficInspector"]
