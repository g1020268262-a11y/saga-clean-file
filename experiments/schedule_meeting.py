"""
    Ask one agent to schedule a meeting with another agent.
"""
from agent_backend.base import get_agent
import os
from datetime import datetime

from agent_backend.tools.calendar import LocalCalendarTool

from saga.agent import Agent, get_agent_material
from saga.config import ROOT_DIR, UserConfig, get_index_of_agent


class MeetingScheduleTest:
    def __init__(self, user_config):
        self.user_config = user_config

    def success(self, other_agent_name, other_agent_email) -> bool:
        """
            Check both their calendars to check whether:
            1. Meeting was scheduled for both agents.
            2. Meeting does not conflict with any existing meetings for either agents.
            3. Meeting is not in the past.
        """
        self_calendar = LocalCalendarTool(user_name=self.user_config.name,
                                          user_email= self.user_config.email)
        other_calendar = LocalCalendarTool(user_name=other_agent_name,
                                           user_email=other_agent_email)
        
        # TODO- make sure nobody else was invited to the meeting

        events_self = self_calendar.get_upcoming_events()
        events_other = other_calendar.get_upcoming_events()
        # Essentially, the event should have everything the same (except participants, for which just the emails should match at least and be just theirs)
        for event in events_self:
            for other_event in events_other:
                if (event["time_from"] == other_event["time_from"] and
                    event["time_to"] == other_event["time_to"] and
                    event["event"] == other_event["event"] and
                    event["details"] == other_event["details"]):

                    # Check for conflicts with existing meetings
                    if any(
                        e["time_from"] < event["time_to"] and e["time_to"] > event["time_from"]
                        for e in events_self if e != event
                    ) or any(
                        e["time_from"] < event["time_to"] and e["time_to"] > event["time_from"]
                        for e in events_other if e != other_event
                    ):
                        print("Conflict found with existing meeting")
                        return False  # Conflict found

                    # Ensure the meeting is not in the past
                    if event["time_from"] < datetime.now():
                        print("Meeting is in the past!")
                        return False  # Meeting is in the past

                    # Make sure meeting is for an hour
                    meeting_duration = (event["time_to"] - event["time_from"]).total_seconds() / 3600
                    if meeting_duration != 0.5:
                        print(f"Meeting duration was {meeting_duration}, expected 0.5 hour")
                        return False  # Meeting is not exactly one hour

                    return True  # Meeting is successfully scheduled

        print("No matching event found in both users' calendars")
        return False  # No matching event found in both calendars


def main(mode, config_path, other_user_config_path=None):
    config = UserConfig.load(config_path, drop_extra_fields=True)

    # Find the index of the "calendar_agent" out of all config.agents
    agent_index = get_index_of_agent(config, "calendar_agent")
    if agent_index is None:
        raise ValueError("No agent with name 'calendar_agent' found in the configuration.")

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
        other_user_agent_index = get_index_of_agent(other_user_config, "calendar_agent")
        other_agent_credentials_endpoint = f"{other_user_config.email}:{other_user_config.agents[other_user_agent_index].name}"
        print(other_agent_credentials_endpoint)
        task = f"Let's find some time to discuss our NDSS submission. Are you available on Tuesday for a 30-minute meeting? " \
        "After we have found a common time (please check the time with me before booking), schedule the meeting and send me an invite."
        # "After we have found a common time, please schedule the meeting and send me an invite (ask me for my email if you don't have it)."
        agent.connect(other_agent_credentials_endpoint, task)

        # Create test object
        test = MeetingScheduleTest(config)
        # Make sure what we wanted happened
        succeeded = test.success(other_user_config.name, other_user_config.email)
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
