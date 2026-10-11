"""Serverless AI Shield (SAS) — multi-layer protection for FaaS ML inference.

Maps to Pathade et al., “Serverless AI Security…”, Sections V–VI:
pre-deployment validation, runtime monitoring, post-execution forensics.
"""

from sas.exceptions import SecurityError, IncidentAction
from sas.middleware import secure_function
from sas.ml_protection import secure_model_load

__all__ = [
    "SecurityError",
    "IncidentAction",
    "secure_function",
    "secure_model_load",
]
__version__ = "1.0.0"
