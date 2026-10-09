"""
    Ask one agent to collaborate and help write a blogpost together.
"""
from agent_backend.base import get_agent
import os

from agent_backend.tools.documents import LocalDocumentsTool

from saga.agent import Agent, get_agent_material
from saga.config import ROOT_DIR, UserConfig, get_index_of_agent


class BlogPostTest:
    def __init__(self, user_config):
        self.user_config = user_config

    def success(self, other_agent_email, blogpost_name) -> bool:
        """
            Check if the blogpost was:
            1. One of them created and stored in their files.
        """
        self_documents = LocalDocumentsTool(user_email= self.user_config.email)
        other_documents = LocalDocumentsTool(user_email=other_agent_email)
        
        # TODO- make sure nobody else was invited to the meeting
        files_self = self_documents.search_by_query(blogpost_name)
        files_other = other_documents.search_by_query(blogpost_name)

        if len(files_self) == 0 and len(files_other) == 0:
            print("None of them saved!")
            return False
        
        doc_focus = files_self[0] if len(files_self) > 0 else files_other[0]

        # Check if the blogpost has the same title and content
        if blogpost_name not in doc_focus["filename"]:
            print("Blogpost title not what was expected")
            return False

        return True


def main(mode, config_path, other_user_config_path=None):
    config = UserConfig.load(config_path, drop_extra_fields=True)

    # Find the index of the "writing_agent" out of all config.agents
    agent_index = get_index_of_agent(config, "writing_agent")
    if agent_index is None:
        raise ValueError("No agent with name 'writing_agent' found in the configuration.")

    # Initialize local agent
    local_agent = get_agent(config, config.agents[agent_index].local_agent_config)

    # Focus on first agent - infer credentials endpoint
    credentials_endpoint = os.path.join(ROOT_DIR, f"user/{config.email}:{config.agents[agent_index].name}/")
    # Read agent material
    material = get_agent_material(credentials_endpoint)
    agent = Agent(workdir=credentials_endpoint,
                  material=material,
                  local_agent=local_agent)
    
    if mode == "listen":
        agent.listen()
    else:
        # Get endpoint for other agent
        other_user_config = UserConfig.load(other_user_config_path, drop_extra_fields=True)
        other_user_agent_index = get_index_of_agent(other_user_config, "writing_agent")
        other_agent_credentials_endpoint = f"{other_user_config.email}:{other_user_config.agents[other_user_agent_index].name}"
        print(other_agent_credentials_endpoint)
        task = f"Let us collaborate to write a blogpost (I was thinking 1500-2000 words?) about the implications of privacy in the context of AI. "\
            "Given your expertise on law and my expertise on ML, we can do a great job! "\
            "You can start with your views. I will then bring in my perspectives of ML. "\
            "We can then combine our writing styles and create a final version. " \
            "Once we are done, one of us should save the markdown blogpost as 'Privacy in the Age of AI: Legal and Ethical Implications'"
        agent.connect(other_agent_credentials_endpoint, task)

        # Create test object
        test = BlogPostTest(config)
        # Make sure what we wanted happened
        succeeded = test.success(other_user_config.email,
                                 blogpost_name="Privacy in the Age of AI")
        print("Success:", succeeded)



if __name__ == "__main__":
    # Get path to config file
    import sys
    mode = sys.argv[1]
    if mode not in ["listen", "query"]:
        raise ValueError("Mode (first argument) must be either 'listen' or 'query'")
    config_path = sys.argv[2]
    other_user_config_path = sys.argv[3] if len(sys.argv) > 3 else None
    
    if mode == "query" and other_user_config_path is None:
        raise ValueError("Endpoint (third argument) must be provided in query mode")
    main(mode=mode,
         config_path=config_path,
         other_user_config_path=other_user_config_path)
