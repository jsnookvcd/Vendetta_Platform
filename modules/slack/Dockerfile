FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
RUN useradd -r -u 10009 slack
USER slack
EXPOSE 8000
# No proxy headers: the responder is not behind the ALB (Socket Mode, console over
# SSM port forwarding), so X-Forwarded-For is never trusted for the login limiter.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-proxy-headers"]
