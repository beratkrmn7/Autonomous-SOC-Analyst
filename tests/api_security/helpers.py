from agent.config import Settings


def make_settings(**overrides) -> Settings:
    values = {
        "app_env": "test",
        "auth_mode": "disabled",
        "llm_enabled": False,
        "trusted_hosts": ["localhost", "127.0.0.1", "testserver"],
    }
    values.update(overrides)
    return Settings(**values)
