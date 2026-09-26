class ReleaseGateError(Exception):
    """Exception levée quand une règle du release gate échoue"""
    pass

def validate_release_gate(config: dict):
    """
    Z-CORE V1 0.3.2-local Release Gate
    Refuse le démarrage si config non conforme en release
    """
    env = config.get("env", "dev")
    if env != "release":
        return True  # pas de gate en dev

    secret = config.get("secret", "")
    bind_host = config.get("bind_host", "127.0.0.1")
    local_only = config.get("local_only", True)
    azure = config.get("azure", {})

    # GATE-1: secret par défaut ou vide
    if secret == "CHANGE_ME_LOCAL_DEV_ONLY" or secret == "":
        raise ReleaseGateError("GATE-1: secret par défaut ou vide en release")

    # GATE-2: bind hors loopback si local_only=true
    if local_only is True and bind_host != "127.0.0.1":
        raise ReleaseGateError("GATE-2: bind != 127.0.0.1 avec local_only=true")

    # GATE-3: local_only=false en release
    if local_only is False:
        raise ReleaseGateError("GATE-3: local_only=false en release")

    # GATE-4: azure live en release
    if azure.get("live", False) is True:
        raise ReleaseGateError("GATE-4: azure.live=true en release")

    return True
