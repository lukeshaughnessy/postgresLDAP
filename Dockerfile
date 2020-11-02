FROM python:3.6-alpine
COPY . /opt/psqlusr
WORKDIR /opt/psqlusr
RUN apk update && apk upgrade
RUN apk -Uuv add build-base openldap-dev postgresql-dev
RUN pip install -r requirements.txt
ENTRYPOINT ["python", "psqlusr_cmd.py"]