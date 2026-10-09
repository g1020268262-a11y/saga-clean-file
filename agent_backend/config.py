"""
    Definitions for configurations.
"""
from dataclasses import dataclass, field
from typing import Optional, List
from simple_parsing.helpers import Serializable


@dataclass
class LocalAgentConfig(Serializable):
    """
    Configuration for a local agent.
    This is specific to the way agents are setup for SAGA, but can be replaced with any configuration that matches the way you want to implement your agents.
    The important part is that 'some' configuration is used to create the agent.
    """
    model: str
    """The actual model (LLM) to use"""
    tools: List[str]
    """List of tools available to the agent."""
    specific_agent_instruction: Optional[str] = ""
    """Specific prompt instructions for the agent"""
    additional_authorized_imports: List[str] = field(default_factory=list)
    """List of additional authorized imports for the agent."""
    api_base: Optional[str] = None
    """API base URL for the agent, if using an API model."""
    model_type: Optional[str] =  "TransformersModel"
    """Type of backbone model for the agent. One of: TransformersModel, HfApiModel (for now; will add support later)"""
    base_agent_type: Optional[str] = "CodeAgent"
    """Wrapper class for the agent. Use one of ['CodeAgent''] (for now; may add support later)"""
    def __post_init__(self):
        if self.model_type in ["OpenAIServerModel"]:
            # Make sure api_base and api_key are set
            if not self.api_base:
                raise ValueError("api_base must be set for OpenAIServerModel")
