FROM python:3.12-slim
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd -r -u 10001 ascent && chown -R ascent /srv
USER ascent
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
