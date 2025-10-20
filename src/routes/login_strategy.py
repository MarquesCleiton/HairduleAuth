import json
import hashlib
import uuid
from datetime import datetime
from core.response import HttpResponse
from .base_strategy import BaseStrategy
from utils.logger import log_info, log_warn, log_error
from core.ddb_client import query_user_by_email, table
from utils.crypto_utils import verify_password
from utils.jwt_utils import generate_access_token, generate_refresh_token


class LoginStrategy(BaseStrategy):
    SERVICE = "hairdule-auth"

    def execute(self, event):
        """Fluxo principal do login"""
        try:
            body = self._parse_body(event)
            email, password = self._validate_fields(body)
            user_item = self._get_user(email)
            self._check_password(password, user_item)

            tokens = self._generate_tokens(user_item)
            self._create_session(user_item["pk"], tokens["refresh_token"], tokens["expires_at"])

            log_info(
                self.SERVICE,
                "Login concluído com sucesso",
                logCode="AUTH-LOGIN-200-FINAL",
                payload={"user_id": user_item.get("pk")}
            )

            return HttpResponse.ok({
                "access_token": tokens["access_token"],
                "refresh_token": tokens["refresh_token"],
                "expires_in": 300,
                "token_type": "Bearer"
            })

        except ValueError as e:
            # Erros de validação conhecidos
            return HttpResponse.bad_request(str(e))
        except PermissionError as e:
            # Erros de autenticação
            return HttpResponse.unauthorized(str(e))
        except Exception as e:
            log_error(self.SERVICE, "Erro inesperado no login", logCode="AUTH-LOGIN-500-FINAL", exc_info=e)
            return HttpResponse.server_error("Erro interno no servidor")

    # ------------------------------------------------------

    def _parse_body(self, event):
        """Valida e converte o body JSON"""
        body_raw = event.get("body")
        if not body_raw:
            log_warn(self.SERVICE, "Login body ausente", logCode="AUTH-LOGIN-400-1")
            raise ValueError("Body ausente ou inválido")

        try:
            body = json.loads(body_raw)
            return body
        except Exception:
            log_warn(self.SERVICE, "Body JSON inválido", logCode="AUTH-LOGIN-400-2", payload={"body": str(body_raw)[:120]})
            raise ValueError("JSON inválido no body")

    # ------------------------------------------------------

    def _validate_fields(self, body):
        """Verifica campos obrigatórios"""
        email = (body.get("email") or "").strip().lower()
        password = (body.get("password") or "").strip()

        missing = [f for f in ["email", "password"] if not body.get(f)]
        if missing:
            log_warn(self.SERVICE, "Campos obrigatórios ausentes", logCode="AUTH-LOGIN-400-3", payload={"missing": missing})
            raise ValueError(f"Campos obrigatórios ausentes: {', '.join(missing)}")

        log_info(self.SERVICE, "Validação inicial OK", logCode="AUTH-LOGIN-200-1", payload={"email_masked": self._mask_email(email)})
        return email, password

    # ------------------------------------------------------

    def _get_user(self, email):
        """Busca o usuário no DynamoDB"""
        try:
            user_item = query_user_by_email(email)
        except Exception as ex:
            log_error(self.SERVICE, "Erro ao consultar DynamoDB", logCode="AUTH-LOGIN-500-1", exc_info=ex)
            raise RuntimeError("Erro ao consultar banco de dados")

        if not user_item:
            log_warn(self.SERVICE, "Usuário não encontrado", logCode="AUTH-LOGIN-404-1", payload={"email": self._mask_email(email)})
            raise PermissionError("E-mail ou senha inválidos")

        return user_item

    # ------------------------------------------------------

    def _check_password(self, password, user_item):
        """Valida a senha com bcrypt"""
        stored_hash = user_item.get("passwordHash")
        if not verify_password(password, stored_hash):
            log_warn(self.SERVICE, "Senha incorreta", logCode="AUTH-LOGIN-401-1", payload={"user": user_item.get("pk")})
            raise PermissionError("E-mail ou senha inválidos")

        log_info(self.SERVICE, "Senha validada com sucesso", logCode="AUTH-LOGIN-200-3", payload={"user": user_item.get("pk")})

    # ------------------------------------------------------

    def _generate_tokens(self, user_item):
        """Gera access e refresh tokens"""
        try:
            user_id = user_item.get("pk")
            business_id = user_item.get("businessId", "BUSINESS#default")
            role = user_item.get("role", "client")
            permissions = user_item.get("permissions", "business:read")

            access_token = generate_access_token(user_id, business_id, role, permissions)
            refresh_token, expires_at = generate_refresh_token()

            log_info(self.SERVICE, "Tokens gerados com sucesso", logCode="AUTH-LOGIN-200-4", payload={"user_id": user_id, "role": role})

            return {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "expires_at": expires_at
            }

        except Exception as ex:
            log_error(self.SERVICE, "Erro ao gerar tokens", logCode="AUTH-LOGIN-500-2", exc_info=ex)
            raise RuntimeError("Erro ao gerar tokens")

    # ------------------------------------------------------

    def _create_session(self, user_id, refresh_token, expires_at):
        """Cria sessão no DynamoDB"""
        try:
            session_id = str(uuid.uuid4())
            refresh_hash = hashlib.sha256(refresh_token.encode("utf-8")).hexdigest()

            table.put_item(
                Item={
                    "pk": user_id,
                    "sk": f"SESSION#{session_id}",
                    "refreshTokenHash": refresh_hash,
                    "expiresAt": expires_at,
                    "revoked": False,
                    "createdAt": datetime.utcnow().isoformat() + "Z"
                }
            )

            log_info(self.SERVICE, "Sessão criada com sucesso", logCode="AUTH-LOGIN-200-5", payload={"session_id": session_id, "user_id": user_id})

        except Exception as ex:
            log_error(self.SERVICE, "Erro ao salvar sessão", logCode="AUTH-LOGIN-500-3", exc_info=ex)
            raise RuntimeError("Erro ao criar sessão")

    # ------------------------------------------------------

    @staticmethod
    def _mask_email(email: str) -> str:
        """Retorna e-mail mascarado para logs seguros"""
        try:
            user, domain = email.split("@", 1)
            masked = user[:2] + "***" if len(user) > 2 else user[:1] + "***"
            return f"{masked}@{domain}"
        except Exception:
            return "***"
