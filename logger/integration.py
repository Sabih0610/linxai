# logger/integration.py
# LoggingHub provides clean callbacks for all LINxAI modules.

from logger.audit import AuditLogger


class LoggingHub:
    """
    Small adapter around AuditLogger.

    Different modules use different callback styles.
    This class normalizes them all into one central audit log.
    """

    def __init__(self, log_path="/opt/linxai/logs/audit.jsonl"):
        self.audit = AuditLogger(log_path=log_path)

    def ai(self, user_input: str, plan: dict):
        return self.audit.log_ai_intent(user_input, plan)

    def validation(self, plan: dict, validation: dict):
        return self.audit.log_validation(plan, validation)

    def execution(self, result: dict):
        return self.audit.log_execution(result)

    def ebpf_callback(self, record: dict):
        return self.audit.log_ebpf_event(record)

    def resource_callback(self, event_type: str, payload: dict):
        return self.audit.log_resource_event(event_type, payload)

    def vps_callback(self, event_type: str, payload: dict):
        return self.audit.log_vps_event(event_type, payload)

    def voice_callback(self, event_type: str, payload: dict):
        return self.audit.log_voice_event(event_type, payload)

    def generic(self, module: str, event_type: str, payload: dict):
        return self.audit.log(module, event_type, payload)