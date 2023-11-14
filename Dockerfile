FROM v2fly/v2fly-core:v5.4.1

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories

RUN apk update && apk add --no-cache python3 py3-pip busybox-extras supervisor 

COPY requirements.txt /opt/app/requirements.txt

RUN pip install -r /opt/app/requirements.txt

COPY src /opt/app
COPY supervisord.conf /etc/supervisord.conf

WORKDIR /opt/app

ENV V2RAY_CONFIG_PATH=/etc/v2ray/config.json
ENV V2RAY_IN_DOCKER=true
ENV V2RAY_SUB_URL=https://s.suying666.info/link/XEbX4b7er9eZrEMz?sub=3

RUN echo "*/1 * * * * python3 /opt/app/v2ray_auto.py >> /opt/app/v2ray_auto.log" > /etc/crontabs/root

ENTRYPOINT ["supervisord", "-c", "/etc/supervisord.conf"]