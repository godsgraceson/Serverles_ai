"""Backward-compatible import path used by existing tests."""

from functions.inference.handler import inference_handler, lambda_handler

__all__ = ["inference_handler", "lambda_handler"]
