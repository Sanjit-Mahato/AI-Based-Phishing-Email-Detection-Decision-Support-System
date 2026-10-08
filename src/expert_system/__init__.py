"""Expert system module exports."""
from .knowledge_base import HornRule, KnowledgeBase
from .forward_chaining import ForwardChainingEngine
from .backward_chaining import BackwardChainingEngine, ProofNode

__all__ = [
    "HornRule",
    "KnowledgeBase",
    "ForwardChainingEngine",
    "BackwardChainingEngine",
    "ProofNode"
]
