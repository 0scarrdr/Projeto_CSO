from soar.integrations.config_verify import verify_config

def verify_config_action(incident, file_path: str):
    return verify_config(file_path)
