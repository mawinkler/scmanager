FROM python:3

RUN pip install requests
RUN mkdir /app

COPY ./scmanager.py /app
WORKDIR /app

CMD ["python", "/app/scmanager.py"]
