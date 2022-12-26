FROM python:3.8

RUN \
    apt-get update \
    && apt-get install -y \
    build-essential

ADD . /app

WORKDIR /app

RUN python -m pip install -r requirements.txt

CMD ["python", "./rest_target.py"]
