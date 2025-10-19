from core.router import RouteStrategyFactory
from utils.logger import log_info
from core.response import HttpResponse

def handler(event, context):
    route = event.get("rawPath", "")
    log_info("hairdule-auth", f"Request received on {route}", logCode="AUTH-ENTRY-001")
    strategy = RouteStrategyFactory.resolve(route)
    if not strategy:
        return HttpResponse.not_found("Route not found")
    return strategy.execute(event)
