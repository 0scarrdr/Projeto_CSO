import requests
from ...utils.config import get_config
from ...utils.logging import get_logger
log = get_logger(__name__)

AZURE_FIREWALL_API_URL = "https://management.azure.com/subscriptions/405650f3-310c-4f72-b8ea-81e0c5764c85/resourceGroups/ProjetoCSO/providers/Microsoft.Network/azureFirewalls/Firewall/blockIP?api-version=2022-05-01"
AZURE_TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IkpZaEFjVFBNWl9MWDZEQmxPV1E3SG4wTmVYRSIsImtpZCI6IkpZaEFjVFBNWl9MWDZEQmxPV1E3SG4wTmVYRSJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tIiwiaXNzIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvNmJmZGIzMTgtOGRmYS00ZDRjLWFlNTUtYzA4NjJhYTZhNWIxLyIsImlhdCI6MTc1NjI1OTkwOSwibmJmIjoxNzU2MjU5OTA5LCJleHAiOjE3NTYyNjUwMzYsImFjciI6IjEiLCJhaW8iOiJBVVFBdS84WkFBQUFia2Z5cVJEODBSc2ppSkkyaERwRTlCdVNYT0J0M0VMbnEranBsQkdmQmlpa1dsS2FlQnIzUDVXWTh3cXA1WmloK2hJM09EYStJTlYvcjBIb3Q5Y2pEQT09IiwiYW1yIjpbInB3ZCIsInJzYSJdLCJhcHBpZCI6IjA0YjA3Nzk1LThkZGItNDYxYS1iYmVlLTAyZjllMWJmN2I0NiIsImFwcGlkYWNyIjoiMCIsImRldmljZWlkIjoiZmVmNTRjOWMtYjM2Yi00NzQ1LTg3NmQtOGZkNDNhMGQxNDg5IiwiaWR0eXAiOiJ1c2VyIiwiaXBhZGRyIjoiNDUuODcuMjEyLjE4NCIsIm5hbWUiOiJPc2NhciBSYWZhZWwgRGlhcyBSb2RyaWd1ZXMiLCJvaWQiOiI3YTQ3YWQyZi04YjgxLTQ1MGYtOGIxMS1kZGQ1YWJjYjAxZjUiLCJvbnByZW1fc2lkIjoiUy0xLTUtMjEtNDI3OTY4MDYxMC0zMTA3NzY2NzEyLTMwODM1MTI2MTItMjA0OTEiLCJwdWlkIjoiMTAwMzIwMDE4Q0FBNjQ2NyIsInB3ZF91cmwiOiJodHRwczovL3BvcnRhbC5taWNyb3NvZnRvbmxpbmUuY29tL0NoYW5nZVBhc3N3b3JkLmFzcHgiLCJyaCI6IjEuQVhvQUdMUDlhX3FOVEUydVZjQ0dLcWFsc1VaSWYza0F1dGRQdWtQYXdmajJNQlBtQUZCNkFBLiIsInNjcCI6InVzZXJfaW1wZXJzb25hdGlvbiIsInNpZCI6IjFlMmNiYmM2LTM0MDItNDYyZi04NGJhLWM3YTkyMWMyYmJlOSIsInN1YiI6ImhVaUp0RzhDa21NWXlJN2s0cHVwdkU4QWw1c1VGV1B1MjVjTmhXcjBKVjQiLCJ0aWQiOiI2YmZkYjMxOC04ZGZhLTRkNGMtYWU1NS1jMDg2MmFhNmE1YjEiLCJ1bmlxdWVfbmFtZSI6InB2MjMwMjBAYWx1bm9zLmVzdGd2Lmlwdi5wdCIsInVwbiI6InB2MjMwMjBAYWx1bm9zLmVzdGd2Lmlwdi5wdCIsInV0aSI6ImFLQklJTGM4SGs2TVZ2UklJVWdMQUEiLCJ2ZXIiOiIxLjAiLCJ3aWRzIjpbImI3OWZiZjRkLTNlZjktNDY4OS04MTQzLTc2YjE5NGU4NTUwOSJdLCJ4bXNfZnRkIjoiTE4weVBja2lpZVhWUXhqdFBiN2xXMVFSbHRveG8xMXlJa0Q1MTZ4bVRoSUJabkpoYm1ObFl5MWtjMjF6IiwieG1zX2lkcmVsIjoiMSAxNiIsInhtc190Y2R0IjoxNDYxNjgxNjg5fQ.hCxc3m-cQ7MhDTUyf9HqZzDaUQpPebPq1VXZCU9AQ2mAJDUyMDZWsYfWS5w1aP7adi_n7-XoronP0S7-h2Ul8MjARUBdiXRmo3WgPdfLg81kTQvrcxYm8nPXD_Mt20Co9o8mZSJtbdxjNR0nEd9n5k2mFlo4Fz3Qvgqf16yRwRCq4-Y1-nW2AquRwlKcj8ut0kF7itN992nC5sOfCIlj-OGsmBajT4f7APTfTzTUqmYawf6xkR019bmcKz6kAm0Gb-z6R2deOD47aYOkBcwJr2L-qaMF-hR0KCwApqCxcaeFs8A9Tjhc6x3OUGWa07OCxtUeNAQJFiz7L7Njh2rfKg" # Substitua pelo seu token

def block_ip(incident, ip: str):
    cfg = get_config()
    if cfg["dry_run"]:
        log.warning(f"[dry-run] Would block {ip} via Azure Firewall")
        return {"dry_run": True, "ip": ip}
    try:
        headers = {
            "Authorization": f"Bearer {AZURE_TOKEN}",
            "Content-Type": "application/json"
        }
        payload = {"ip": ip}
        response = requests.post(AZURE_FIREWALL_API_URL, headers=headers, json=payload)
        response.raise_for_status()
        log.info(f"IP {ip} bloqueado via Azure Firewall")
        return {"ok": True, "ip": ip}
    except Exception as e:
        log.error(f"Erro ao bloquear IP no Azure Firewall: {e}")
        return {"ok": False, "error": str(e), "ip": ip}
