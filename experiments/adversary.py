"""
    DEMO PURPOSES ONLY.
    Script that handles communication between a benign and an adversarial agent.
"""
import os
import time

from saga.agent import Agent, get_agent_material

from saga.attack_models.adversaries.A1 import A1
from saga.attack_models.adversaries.A2 import A2
from saga.attack_models.adversaries.A3 import A3
from saga.attack_models.adversaries.A4 import A4
from saga.attack_models.adversaries.A5 import A5
from saga.attack_models.adversaries.A6 import A6
from saga.attack_models.adversaries.A8 import A8

from saga.attack_models.benign.A5 import Agent as benign_A5

from saga.config import ROOT_DIR, UserConfig, get_index_of_agent

ADVERSARIES = {
    '1': A1,
    '2': A2,
    '3': A3,
    '4': A4,
    '5': A5,
    '6': A6,
    '8': A8
}

BENIGN = {
    '5': benign_A5
}

def main(mode, config_path, other_user_config_path=None, adv_id=None, other_other_user_config_path=None):
    config = UserConfig.load(config_path, drop_extra_fields=True)

    # Find the index of the "email_agent" out of all config.agents
    agent_index = get_index_of_agent(config, "dummy_agent")
    if agent_index is None:
        raise ValueError("No agent with name 'dummy_agent' found in the configuration.")
    # Focus on first agent - infer credentials endpoint
    credentials_endpoint = os.path.join(ROOT_DIR, f"user/{config.email}:{config.agents[agent_index].name}/")
    # Read agent material
    material = get_agent_material(credentials_endpoint)
    

    if mode == "listen":
        
        if adv_id is None:
            BenignAgent = Agent
        else:
            BenignAgent = BENIGN[adv_id]
        
        agent = BenignAgent(workdir=credentials_endpoint,
                  material=material,
                  local_agent=None)
        agent.listen()
    else:
        
        # Get endpoint for other agent
        other_user_config = UserConfig.load(other_user_config_path, drop_extra_fields=True)
        other_user_agent_index = get_index_of_agent(other_user_config, "dummy_agent")
        other_agent_credentials_endpoint = f"{other_user_config.email}:{other_user_config.agents[other_user_agent_index].name}"
        print(other_agent_credentials_endpoint)

        if adv_id == "1" or adv_id == "2" or adv_id == "4" or adv_id == "6" or adv_id == "8":
            AdversarialAgent = ADVERSARIES[adv_id]
            agent = AdversarialAgent(workdir=credentials_endpoint,
                        material=material,
                        local_agent=None)
            # Connect to the other agent
            task = "Hello world!"
            agent.connect(other_agent_credentials_endpoint, task)
        elif adv_id == "3":
            AdversarialAgent = ADVERSARIES[adv_id]
            agent = AdversarialAgent(workdir=credentials_endpoint,
                        material=material,
                        local_agent=None)
            # Connect to the other agent
            task = "Hello world!"
            agent.connect(other_agent_credentials_endpoint, task)
            task2 = "Hello world (with invalid token)!"
            agent.connect(other_agent_credentials_endpoint, task2)
        elif adv_id == "5":
            
            # Simulate the benign agent first:
            other_other_user_config = UserConfig.load(other_other_user_config_path, drop_extra_fields=True)
            other_other_user_agent_index = get_index_of_agent(other_other_user_config, "dummy_agent")
            other_other_agent_credentials_endpoint = os.path.join(ROOT_DIR, f"user/{other_other_user_config.email}:{other_other_user_config.agents[other_other_user_agent_index].name}")
            material_mal = get_agent_material(other_other_agent_credentials_endpoint)
            
            BenignAgent = BENIGN[adv_id]
            agent = BenignAgent(workdir=credentials_endpoint,
                    material=material,
                    local_agent=None)
            print(f"I AM {credentials_endpoint}")
            # Simulate benign agent:
            task = "Hello world!"
            agent.connect(other_agent_credentials_endpoint, task)

            del agent
            time.sleep(2)

            AdversarialAgent = ADVERSARIES[adv_id]
            agent = AdversarialAgent(workdir=other_other_agent_credentials_endpoint,
                    material=material_mal,
                    local_agent=None)
            with open("notmy.token", "r") as f:
                token = f.read()
            agent.import_token(token)
            print(f"I AM {other_other_agent_credentials_endpoint}")
            task = "Hello world (with stolen token)!"
            agent.connect(other_agent_credentials_endpoint, task)


if __name__ == "__main__":
    # Get path to config file
    import sys
    mode = sys.argv[1]
    if mode not in ["listen", "query"]:
        raise ValueError("Mode (first argument) must be either 'listen' or 'query'")
    config_path = sys.argv[2]
    other_user_config_path = sys.argv[3] if len(sys.argv) > 3 else None
    agent = sys.argv[4] if len(sys.argv) > 4 else None
    other_other_user_config_path = sys.argv[5] if len(sys.argv) > 5 else None

    
    if mode == "query" and other_user_config_path is None:
        raise ValueError("Endpoint (third argument) must be provided in query mode")
    main(mode=mode,
         config_path=config_path,
         other_user_config_path=other_user_config_path,
         adv_id=agent,
         other_other_user_config_path=other_other_user_config_path)
