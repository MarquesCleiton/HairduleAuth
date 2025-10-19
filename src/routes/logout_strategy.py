from core.response import HttpResponse
from .base_strategy import BaseStrategy

class LogoutStrategy(BaseStrategy):
    def execute(self, event):
        # 🧠 Futuramente: revogar sessão no DynamoDB
        return HttpResponse.ok({"message": "Logout route working"})
