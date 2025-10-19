from routes.login_strategy import LoginStrategy
from routes.refresh_strategy import RefreshStrategy
from routes.logout_strategy import LogoutStrategy

class RouteStrategyFactory:
    @staticmethod
    def resolve(route: str):
        if route.endswith("/login"):
            return LoginStrategy()
        elif route.endswith("/refresh"):
            return RefreshStrategy()
        elif route.endswith("/logout"):
            return LogoutStrategy()
        return None
