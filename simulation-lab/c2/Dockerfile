FROM python:3.12-slim
WORKDIR /app
COPY server.py ./
ENV PORT=9999 LOG_DIR=/logs
EXPOSE 9999
CMD ["python", "server.py"]
