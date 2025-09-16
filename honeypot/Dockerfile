FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY honeypot_app.py .
RUN mkdir -p /app/templates /app/data
EXPOSE 5000
CMD ["python", "honeypot_app.py"]

