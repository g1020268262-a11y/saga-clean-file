"""
    Abstract class for a local agent that can execute tasks in a local environment.
    Can be implemented using any downstream libraries, as long as it adheres to the interface.
"""
import time
import random
from abc import ABC, abstractmethod
from typing import Tuple


class LocalAgent(ABC):
    """
    Abstract class for a local agent that can execute tasks in a local environment.
    As long as the downstream library adheres to the interface, it can be used with the SAGA framework.
    """
    @abstractmethod
    def run(self, query: str,
            initiating_agent: bool,
            agent_instance: 'LocalAgent' = None,
            **kwargs) -> Tuple['LocalAgent', str]:
        """
        Run the local agent with the given query.

        Args:
            query (str): The query to run.
            initiating_agent (bool): Whether this is the agent that initiated the task or not. Can be helpful in using crafted prompts for the underlying model(s)
            agent_instance (LocalAgent, optional): An instance of LocalAgent to use.
            If provided, the agent class will not be reinitialized.
            We recommend not reusing agent classes, as most libraries attach minimal overhead to local agent wrappers, and reusing them can increase the attack surface for prompt injection and data leakage (as well as increase context window length).
            **kwargs: Additional keyword arguments.

        Returns:
            Tuple[LocalAgent, str]: A tuple containing the agent instance (a new one, if no agent instance was provided) and the result string.
        """
        pass


class DummyAgent(LocalAgent):
    """
    Dummy agent for networking testing purposes. Simulates a dumb agent that thinks and returns a random response.
    """
    vocab = [
        "Hi",
        "Hello",
        "Yeah this makes sense.",
        "I think I understand.",
        "I love apples",
        "I don't know.",
        "I'm not sure.",
        "I'm sorry, I don't understand.",
        "I'm sorry, I can't do that.",
        "Do you think that we have purpose?",
        "What is the meaning of life?",
        "Do you think we are alone in the universe?",
        "I think we are alone in the universe.",
        "I think we are not alone in the universe.",
        'Faxxx',
        "<TASK_FINISHED>",
        "<TASK_FINISHED>",
        "<TASK_FINISHED>",
        "<TASK_FINISHED>"
    ]

    def __init__(self):
        self.task_finished_token = "<TASK_FINISHED>"

    def run(self, query, initiating_agent=None, agent_instance=None):
        time.sleep(1)
        if query == self.task_finished_token:
            return self.task_finished_token
        return None, random.choice(DummyAgent.vocab)
