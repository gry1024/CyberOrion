# CyberOrion backend container - CloudBase Cloud Run
FROM python:3.10-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends gcc curl && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir cai-framework==0.5.10 fastapi==0.115.14 uvicorn==0.29.0 pyyaml==6.0.3 numpy==2.2.6 openai==1.75.0 "reportlab>=4.2,<6"

COPY server.py .
COPY cyberorion/ ./cyberorion/
COPY scenarios/ ./scenarios/

ENV CAI_GUARDRAILS=false
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

CMD ["python", "server.py"]
