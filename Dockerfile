FROM python:3.6

RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app

COPY requirements.txt /usr/src/app/

RUN pip3 install --no-cache-dir -r requirements.txt
RUN pip3 install --no-cache-dir gunicorn

COPY . /usr/src/app

EXPOSE 8080

ENV WORKERS=4

CMD gunicorn -w ${WORKERS} -b 0.0.0.0:8080 run:app