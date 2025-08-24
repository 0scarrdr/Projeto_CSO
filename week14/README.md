# Week 14 — Final
- FastAPI service
- Docker/Docker Compose deployment
- End-to-end demo script + artifacts folders mounted
## Run
```bash
docker compose up --build
# then POST an event:
curl -X POST http://localhost:8080/events -H 'Content-Type: application/json' -d '{"event":{"source":"log","message":"failed login from 1.2.3.4 to root","src_ip":"1.2.3.4","host_id":"srv-01"}}'
```
