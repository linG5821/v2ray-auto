FROM v2fly/v2fly-core:latest


RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories

RUN RUN apk update && apk add --no-cache python3 py3-pip cron

COPY requirements.txt /opt/app/requirements.txt

RUN pip install -r /opt/app/requirements.txt

ENV V2RAY_CONFIG_PATH=/etc/v2ray/config.json

COPY src /opt/app

WORKDIR /opt/app


RUN echo "*/1 * * * * python /opt/app/v2ray_auto.py >> /opt/app/v2ray_auto.log" > /etc/cron.d/v2ray_auto && \
  chmod 0644 /etc/cron.d/v2ray_auto

CMD cron -f