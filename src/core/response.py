import json

def _json(obj):
    return json.dumps(obj, ensure_ascii=False)

class HttpResponse:
    @staticmethod
    def ok(body):
        return {"statusCode": 200, "body": _json(body)}

    @staticmethod
    def created(body):
        return {"statusCode": 201, "body": _json(body)}

    @staticmethod
    def bad_request(message, code="BAD_REQUEST", details=None):
        return {
            "statusCode": 400,
            "body": _json({"error": {"code": code, "message": message, "details": details or {}}})
        }

    @staticmethod
    def unauthorized(message="Unauthorized", code="UNAUTHORIZED"):
        return {"statusCode": 401, "body": _json({"error": {"code": code, "message": message}})}

    @staticmethod
    def forbidden(message="Forbidden", code="FORBIDDEN"):
        return {"statusCode": 403, "body": _json({"error": {"code": code, "message": message}})}

    @staticmethod
    def not_found(message="Not Found", code="NOT_FOUND"):
        return {"statusCode": 404, "body": _json({"error": {"code": code, "message": message}})}

    @staticmethod
    def unprocessable(message="Unprocessable Entity", code="UNPROCESSABLE", details=None):
        return {
            "statusCode": 422,
            "body": _json({"error": {"code": code, "message": message, "details": details or {}}})
        }

    @staticmethod
    def server_error(message="Internal Server Error", code="INTERNAL_ERROR"):
        return {"statusCode": 500, "body": _json({"error": {"code": code, "message": message}})}
