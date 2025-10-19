import json
import traceback
from datetime import datetime
import uuid


def _base(service, level, message, **kwargs):
    """Log estruturado com suporte a stacktrace e payloads adicionais"""
    log = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "level": level,
        "service": service,
        "correlationId": kwargs.get("correlationId", str(uuid.uuid4())),
        "logCode": kwargs.get("logCode"),
        "logMessage": message,
        "payload": kwargs.get("payload"),
    }

    # Se houver exceção no contexto, adiciona stacktrace
    exc = kwargs.get("exc_info")
    if exc:
        log["stacktrace"] = traceback.format_exception(
            type(exc),  # tipo da exceção
            exc,        # instância
            exc.__traceback__  # traceback
        )

    # Imprime log no formato JSON (ideal para CloudWatch)
    print(json.dumps(log, ensure_ascii=False))


def log_info(service, message, **kwargs):
    _base(service, "INFO", message, **kwargs)


def log_warn(service, message, **kwargs):
    _base(service, "WARN", message, **kwargs)


def log_error(service, message, **kwargs):
    """Captura automaticamente o stacktrace, se não for informado"""
    if "exc_info" not in kwargs:
        import sys
        _, exc_value, _ = sys.exc_info()
        if exc_value:
            kwargs["exc_info"] = exc_value
    _base(service, "ERROR", message, **kwargs)
