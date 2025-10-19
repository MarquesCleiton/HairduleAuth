import os
import traceback
import boto3
from botocore.exceptions import ClientError
from utils.logger import log_info, log_error

TABLE_NAME = os.getenv("TABLE_NAME", "HairduleTB")
REGION = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
SERVICE = os.getenv("SERVICE_NAME", "hairdule-auth")


def get_dynamodb_resource():
    """
    Cria o cliente DynamoDB, apontando para o endpoint local se definido.
    """
    endpoint = os.getenv("DYNAMODB_ENDPOINT")
    try:
        if endpoint:
            log_info(SERVICE, f"Conectando ao DynamoDB Local ({endpoint})", logCode="CORE-DDB-001")
            return boto3.resource("dynamodb", region_name=REGION, endpoint_url=endpoint)
        else:
            log_info(SERVICE, f"Conectando ao DynamoDB AWS (região {REGION})", logCode="CORE-DDB-002")
            return boto3.resource("dynamodb", region_name=REGION)
    except Exception as e:
        log_error(
            SERVICE,
            "Erro ao inicializar cliente DynamoDB",
            logCode="CORE-DDB-500-1",
            payload={"error": str(e)},
            stacktrace=traceback.format_exc()
        )
        raise


dynamodb = get_dynamodb_resource()
table = dynamodb.Table(TABLE_NAME)


def query_user_by_email(email: str):
    """
    Busca um usuário pelo e-mail no índice GSI_EMAIL.
    Retorna o item completo se encontrado, senão None.
    """
    try:
        log_info(
            SERVICE,
            "Consultando usuário por e-mail",
            logCode="CORE-DDB-QUERY-001",
            payload={"email_masked": _mask_email(email)}
        )

        response = table.query(
            IndexName="GSI_EMAIL",
            KeyConditionExpression="email = :e",
            ExpressionAttributeValues={":e": email.lower()}
        )

        items = response.get("Items", [])
        count = len(items)

        log_info(
            SERVICE,
            "Consulta finalizada com sucesso",
            logCode="CORE-DDB-QUERY-200",
            payload={"totalItems": count, "email_masked": _mask_email(email)}
        )

        return items[0] if items else None

    except ClientError as e:
        log_error(
            SERVICE,
            "Erro do cliente AWS ao consultar DynamoDB",
            logCode="CORE-DDB-QUERY-400",
            payload={"error": e.response["Error"], "email": _mask_email(email)},
            stacktrace=traceback.format_exc()
        )
        raise RuntimeError(f"Erro AWS DynamoDB: {e}")

    except Exception as e:
        log_error(
            SERVICE,
            "Erro inesperado ao consultar DynamoDB",
            logCode="CORE-DDB-QUERY-500",
            payload={"error": str(e), "email": _mask_email(email)},
            stacktrace=traceback.format_exc()
        )
        raise RuntimeError(f"Erro interno ao consultar DynamoDB: {e}")


def _mask_email(email: str) -> str:
    """
    Aplica máscara simples em e-mail para logs (sem PII).
    """
    try:
        user, domain = email.split("@", 1)
        masked_user = user[:2] + "***" if len(user) > 2 else user[0] + "***"
        return f"{masked_user}@{domain}"
    except Exception:
        return "***"
