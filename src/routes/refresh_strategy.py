from core.response import HttpResponse
from .base_strategy import BaseStrategy

class RefreshStrategy(BaseStrategy):
    def execute(self, event):
        # 🧠 Futuramente: validar refresh token e gerar novo access token
        return HttpResponse.ok({"message": "Refresh route working"})
