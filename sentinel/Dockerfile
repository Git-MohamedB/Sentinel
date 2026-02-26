FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# Copier tous les fichiers python du dossier sentinel
COPY *.py ./
CMD ["python", "-u", "sentinel.py"]
