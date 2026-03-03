FROM python:3.13-slim

WORKDIR /app

RUN pip install --no-cache-dir --upgrade pip

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY sentinel /app/sentinel
COPY data /app/data
COPY docs /app/docs
COPY scripts /app/scripts
COPY tests /app/tests

EXPOSE 8000

CMD ["python", "-m", "sentinel.api"]
