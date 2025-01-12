# FROM python:3.10
# WORKDIR /app
# COPY . .
# RUN pip3 install -r requirements.txt
# EXPOSE 8501
# ENTRYPOINT ["streamlit", "run", "src/main.py", "--server.address=0.0.0.0", "--server.port=8501"]


# Build stage
FROM python:3.10-slim as builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Runtime stage
FROM python:3.10-slim

WORKDIR /app

RUN useradd -m appuser

COPY --from=builder /root/.local /home/appuser/.local
COPY . .

ENV PATH=/home/appuser/.local/bin:$PATH

RUN chown -R appuser:appuser /home/appuser/.local && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 8501
ENTRYPOINT ["streamlit", "run", "src/main.py", "--server.address=0.0.0.0", "--server.port=8501"]