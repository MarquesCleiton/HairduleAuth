import json
import hashlib
import time
from core.response import HttpResponse
from .base_strategy import BaseStrategy
from utils.logger import log_info, log_warn, log_error
from core.ddb_client import table
from utils.jwt_utils import generate_access_token
from boto3.dynamodb.conditions import Key

class RefreshStrategy(BaseStrategy):
    SERVICE = "hairdule-auth"

    def execute(self, event):
        """Renova o access_token a partir do refresh_token"""
        try:
            body = self._parse_body(event)
            refresh_token = (body.get("refresh_token") or "").strip()

            if not refresh_token:
                log_warn(self.SERVICE, "Refresh token ausente", logCode="AUTH-REFRESH-400-1")
                return HttpResponse.bad_request("Campo 'refresh_token' é obrigatório")

            session_item = self._find_session(refresh_token)
            if not session_item:
                return HttpResponse.unauthorized("Sessão inválida, expirada ou revogada")

            # Dados do usuário e contexto
            user_id = session_item["pk"]
            business_id = session_item.get("businessId", "BUSINESS#default")
            role = session_item.get("role", "client")
            permissions = session_item.get("permissions", "business:read")

            # Novo access token
            access_token = generate_access_token(user_id, business_id, role, permissions)

            log_info(
                self.SERVICE,
                "Access token renovado com sucesso",
                logCode="AUTH-REFRESH-200-2",
                payload={"user_id": user_id, "role": role}
            )

            return HttpResponse.ok({
                "access_token": access_token,
                "expires_in": 300,  # 5 minutos
                "token_type": "Bearer"
            })

        except ValueError as ve:
            log_warn(self.SERVICE, "Erro de validação no body", logCode="AUTH-REFRESH-400-9", payload={"error": str(ve)})
            return HttpResponse.bad_request(str(ve))

        except Exception as e:
            log_error(self.SERVICE, "Erro inesperado no refresh", logCode="AUTH-REFRESH-500-1", exc_info=e)
            return HttpResponse.server_error("Erro interno ao renovar token")

    # ------------------------------------------------------

    def _parse_body(self, event):
        """Valida e converte o body JSON"""
        body_raw = event.get("body")
        if not body_raw:
            raise ValueError("Body ausente ou inválido")
        try:
            return json.loads(body_raw)
        except Exception:
            raise ValueError("JSON inválido no body")

    # ------------------------------------------------------

    def _find_session(self, refresh_token: str):
        """Busca sessão válida via índice GSI_REFRESH_HASH"""
        try:
            refresh_hash = hashlib.sha256(refresh_token.encode("utf-8")).hexdigest()

            response = table.query(
                IndexName="GSI_REFRESH_HASH",
                KeyConditionExpression=Key("refreshTokenHash").eq(refresh_hash)
            )

            items = response.get("Items", [])
            if not items:
                log_warn(self.SERVICE, "Sessão não encontrada", logCode="AUTH-REFRESH-404-1")
                return None

            session = items[0]
            now = int(time.time())

            if session.get("revoked"):
                log_warn(self.SERVICE, "Sessão revogada", logCode="AUTH-REFRESH-403-1", payload={"pk": session.get("pk")})
                return None

            if int(session.get("expiresAt", 0)) < now:
                log_warn(self.SERVICE, "Sessão expirada", logCode="AUTH-REFRESH-401-1", payload={"pk": session.get("pk")})
                return None

            log_info(
                self.SERVICE,
                "Sessão válida para refresh",
                logCode="AUTH-REFRESH-200-1",
                payload={"pk": session.get("pk"), "sk": session.get("sk")}
            )
            return session

        except Exception as ex:
            log_error(self.SERVICE, "Erro ao validar refresh token", logCode="AUTH-REFRESH-500-2", exc_info=ex)
            return None
