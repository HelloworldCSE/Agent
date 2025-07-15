import unittest
from unittest.mock import patch, MagicMock

class TestAssistantAgent(unittest.TestCase):
    @patch('autogen.agentchat.assistant_agent.AssistantAgent')
    def test_assistant_agent_initialization(self, MockAssistantAgent):
        MockAssistantAgent.return_value = MagicMock()
        assistant = MockAssistantAgent(
            name="SecurityAnalyst",
            system_message="You are a cybersecurity expert. Analyze code for vulnerabilities like SQLi, XSS, etc.",
            llm_config={"config_list": []}
        )
        self.assertEqual(assistant.name, "SecurityAnalyst")
        self.assertEqual(assistant.system_message, "You are a cybersecurity expert. Analyze code for vulnerabilities like SQLi, XSS, etc.")

    @patch('autogen.oai.client.create_openai_client')
    def test_missing_openai_dependency(self, MockCreateOpenAIClient):
        MockCreateOpenAIClient.side_effect = ImportError("A module needed for autogen.oai.client.create_openai_client is missing: - 'openai' is not installed.")
        with self.assertRaises(ImportError) as context:
            MockCreateOpenAIClient()
        self.assertEqual(str(context.exception), "A module needed for autogen.oai.client.create_openai_client is missing: - 'openai' is not installed.")

if __name__ == '__main__':
    unittest.main()