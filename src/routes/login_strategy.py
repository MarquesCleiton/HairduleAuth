import json
from core.response import HttpResponse
from .base_strategy import BaseStrategy
from utils.logger import log_info, log_warn, log_error
from core.ddb_client import query_user_by_email
from utils.crypto_utils import verify_password

class LoginStrategy(BaseStrategy):
    def execute(self, event):
        # 1️⃣ Parse do body
        body_raw = event.get("body")
        if not body_raw:
            log_warn("hairdule-auth", "Login body ausente", logCode="AUTH-LOGIN-400-1")
            return HttpResponse.bad_request(
                "Body ausente ou inválido",
                details={"hint": "Envie JSON com email e password"}
            )

        try:
            body = json.loads(body_raw)
        except Exception:
            log_warn(
                "hairdule-auth",
                "Login body não é JSON válido",
                logCode="AUTH-LOGIN-400-2",
                payload={"body": body_raw[:120]}
            )
            return HttpResponse.bad_request(
                "JSON inválido no body",
                details={"hint": "Use application/json"}
            )

        # 2️⃣ Campos obrigatórios
        email = (body.get("email") or "").strip().lower()
        password = (body.get("password") or "").strip()

        missing = []
        if not email:
            missing.append("email")
        if not password:
            missing.append("password")

        if missing:
            log_warn(
                "hairdule-auth",
                "Campos obrigatórios ausentes",
                logCode="AUTH-LOGIN-400-3",
                payload={"missing": missing}
            )
            return HttpResponse.unprocessable(
                "Campos obrigatórios ausentes",
                details={"missing": missing}
            )

        # 3️⃣ Validação inicial OK
        log_info(
            "hairdule-auth",
            "Login validação inicial OK",
            logCode="AUTH-LOGIN-200-1",
            payload={"email_masked": self._mask_email(email)}
        )

        # 4️⃣ Buscar usuário no DynamoDB
        try:
            user_item = query_user_by_email(email)
        
        except Exception as ex:
            log_error(
                "hairdule-auth",
                "Erro ao consultar usuário no DynamoDB",
                logCode="AUTH-LOGIN-500-1",
                payload={"error": str(ex)},
                exc_info=ex
            )

            return HttpResponse.server_error("Erro ao consultar banco de dados")

        # 5️⃣ Usuário não encontrado
        if not user_item:
            log_warn(
                "hairdule-auth",
                "Usuário não encontrado",
                logCode="AUTH-LOGIN-404-1",
                payload={"email": self._mask_email(email)}
            )
            return HttpResponse.unauthorized("E-mail ou senha inválidos")

        # 6️⃣ Usuário encontrado — validar senha
        stored_hash = user_item.get("passwordHash")

        if not verify_password(password, stored_hash):
            log_warn(
                "hairdule-auth",
                "Senha incorreta",
                logCode="AUTH-LOGIN-401-1",
                payload={"email_masked": self._mask_email(email)}
            )
            return HttpResponse.unauthorized("E-mail ou senha inválidos")

        # 7️⃣ Senha válida — segue para geração dos tokens (próximo passo)
        log_info(
            "hairdule-auth",
            "Senha validada com sucesso",
            logCode="AUTH-LOGIN-200-3",
            payload={"pk": user_item.get("pk")}
        )

        return HttpResponse.ok({
            "message": "Senha válida, pronto para gerar tokens",
            "pk": user_item.get("pk")
        })

    @staticmethod
    def _mask_email(email: str) -> str:
        """Retorna e-mail mascarado para logs seguros"""
        try:
            user, domain = email.split("@", 1)
            if len(user) <= 2:
                masked = user[:1] + "***"
            else:
                masked = user[:2] + "***"
            return f"{masked}@{domain}"
        except Exception:
            return "***"
