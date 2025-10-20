import os
import uuid
import jwt
import boto3
from datetime import datetime, timedelta
from utils.logger import log_info, log_warn, log_error


SERVICE = os.getenv("SERVICE_NAME", "hairdule-auth")


def get_jwt_secret() -> str:
    """
    Obtém o segredo do JWT. 
    1️⃣ Tenta usar AUTH_JWT_SECRET (ambiente local/dev)
    2️⃣ Caso não exista, busca AUTH_JWT_SECRET_SSM no Parameter Store
    """
    try:
        secret_env = os.getenv("AUTH_JWT_SECRET")
        if secret_env:
            log_info(SERVICE, "🔐 JWT secret obtido do ambiente", logCode="AUTH-JWT-001")
            return secret_env

        param_name = os.getenv("AUTH_JWT_SECRET_SSM")
        if not param_name:
            raise ValueError("JWT secret não configurado. Defina AUTH_JWT_SECRET ou AUTH_JWT_SECRET_SSM.")

        region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
        ssm = boto3.client("ssm", region_name=region)
        resp = ssm.get_parameter(Name=param_name, WithDecryption=True)

        log_info(SERVICE, "🔐 JWT secret obtido do SSM Parameter Store", logCode="AUTH-JWT-002")
        return resp["Parameter"]["Value"]

    except Exception as e:
        log_error(
            SERVICE,
            "❌ Falha ao obter segredo JWT",
            logCode="AUTH-JWT-500-1",
            payload={"error": str(e)},
            exc_info=e
        )
        raise


def generate_access_token(user_id: str, business_id: str, role: str, permissions: str) -> str:
    """
    Emite um JWT curto (default: 5 min) com payload mínimo e seguro.
    """
    try:
        secret = get_jwt_secret()
        exp_minutes = int(os.getenv("TOKEN_EXP_MINUTES", "5"))
        now = datetime.utcnow()

        payload = {
            "sub": user_id,
            "businessId": business_id,
            "role": role,
            "permissions": permissions,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=exp_minutes)).timestamp()),
            "iss": "hairdule-auth"
        }

        token = jwt.encode(payload, secret, algorithm="HS256")

        log_info(
            SERVICE,
            "✅ Access token gerado com sucesso",
            logCode="AUTH-JWT-200-1",
            payload={"user_id": user_id, "role": role, "expMinutes": exp_minutes}
        )

        return token

    except Exception as e:
        log_error(
            SERVICE,
            "❌ Erro ao gerar access token",
            logCode="AUTH-JWT-500-2",
            payload={"user_id": user_id, "error": str(e)},
            exc_info=e
        )
        raise


def generate_refresh_token():
    """
    Gera um token opaco (uuid4) e a expiração (default: +7 dias).
    Retorna: (refresh_token, expires_at)
    """
    try:
        exp_days = int(os.getenv("REFRESH_EXP_DAYS", "7"))
        refresh_token = str(uuid.uuid4())
        expires_at = int((datetime.utcnow() + timedelta(days=exp_days)).timestamp())

        log_info(
            SERVICE,
            "🔁 Refresh token gerado com sucesso",
            logCode="AUTH-JWT-200-2",
            payload={"expiresAt": expires_at, "expDays": exp_days}
        )

        return refresh_token, expires_at

    except Exception as e:
        log_error(
            SERVICE,
            "❌ Erro ao gerar refresh token",
            logCode="AUTH-JWT-500-3",
            payload={"error": str(e)},
            exc_info=e
        )
        raise


def verify_access_token(token: str) -> dict:
    """
    Decodifica e valida um access token. 
    Levanta ValueError em caso de expiração ou token inválido.
    """
    try:
        secret = get_jwt_secret()
        decoded = jwt.decode(token, secret, algorithms=["HS256"])

        log_info(
            SERVICE,
            "🧩 Access token validado com sucesso",
            logCode="AUTH-JWT-200-3",
            payload={"sub": decoded.get("sub"), "role": decoded.get("role")}
        )

        return decoded

    except jwt.ExpiredSignatureError as e:
        log_warn(
            SERVICE,
            "⚠️ Access token expirado",
            logCode="AUTH-JWT-401-1",
            payload={"tokenSnippet": token[:16] + "..."}
        )
        raise ValueError("Token expirado") from e

    except jwt.InvalidTokenError as e:
        log_warn(
            SERVICE,
            "⚠️ Access token inválido",
            logCode="AUTH-JWT-401-2",
            payload={"tokenSnippet": token[:16] + "..."}
        )
        raise ValueError("Token inválido") from e

    except Exception as e:
        log_error(
            SERVICE,
            "❌ Erro inesperado ao validar token",
            logCode="AUTH-JWT-500-4",
            payload={"error": str(e)},
            exc_info=e
        )
        raise
