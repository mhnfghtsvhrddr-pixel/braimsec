FROM python:3.12-slim

WORKDIR /app

COPY api/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY api/ ./api/
COPY dashboard/ ./dashboard/

# Non-root runtime user (uid/gid 10001, same as the production images).
# /app is chowned so the dev server can write its local DB/__pycache__.
RUN groupadd --gid 10001 braimsec \
    && useradd --uid 10001 --gid 10001 \
        --home-dir /home/braimsec --create-home braimsec \
    && chown -R braimsec:braimsec /app /home/braimsec
ENV HOME=/home/braimsec

WORKDIR /app/api

EXPOSE 8000
USER 10001

CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]
