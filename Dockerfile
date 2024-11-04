FROM v2ray-auto-base:latest

ENV V2RAY_CONFIG_PATH=/etc/v2ray/config.json
ENV V2RAY_IN_DOCKER=true
ENV V2RAY_SUB_URL=''

COPY requirements.txt /opt/app/requirements.txt
COPY src /opt/app
COPY supervisord.conf /etc/supervisord.conf

WORKDIR /opt/app

RUN \ 
  # pip install -r /opt/app/requirements.txt && \ 
  echo "*/5 * * * * python3 /opt/app/v2ray_auto.py >> /opt/app/v2ray_auto.log" > /etc/crontabs/root

ENTRYPOINT ["supervisord", "-c", "/etc/supervisord.conf"]