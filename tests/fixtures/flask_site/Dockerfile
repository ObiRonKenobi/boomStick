FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
EXPOSE 8080
CMD ["python", "-m", "flask", "--app", "app", "run", "-h", "0.0.0.0", "-p", "8080"]
