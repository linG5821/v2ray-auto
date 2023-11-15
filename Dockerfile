FROM v2fly/v2fly-core:v5.4.1

ENV V2RAY_CONFIG_PATH=/etc/v2ray/config.json
ENV V2RAY_IN_DOCKER=true
ENV V2RAY_SUB_URL=''

COPY requirements.txt /opt/app/requirements.txt
COPY src /opt/app
COPY supervisord.conf /etc/supervisord.conf

WORKDIR /opt/app

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories && \
  apk update && apk add --no-cache python3 py3-pip busybox-extras supervisor && \
  pip install -r /opt/app/requirements.txt && \
  echo "*/5 * * * * python3 /opt/app/v2ray_auto.py >> /opt/app/v2ray_auto.log" > /etc/crontabs/root

ENTRYPOINT ["supervisord", "-c", "/etc/supervisord.conf"]