from os import getenv
from time import sleep
import requests
import base64
import json
import re
import subprocess
from datetime import datetime


def get_sub_url():
    return getenv('V2RAY_SUB_URL', '')

def get_area_filter():
    return getenv('V2RAY_AREA_FILTER', '新用户|过期|剩余')

def get_proxy_url(): 
    return getenv('V2RAY_CUR_PROXY', 'socks5://127.0.0.1:20810')

def get_config_path():
    return getenv('V2RAY_CONFIG_PATH', '/usr/local/etc/v2ray/config.json')

def is_docker():
   return getenv('V2RAY_IN_DOCKER', 'false') == 'true'

def log(content):
   formatted_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
   print(formatted_time + " " + content)

def parse_vmess(vmess_link):
    # 从链接中提取有效部分（去除 vmess://）
    vmess_data = vmess_link[8:]
    # 进行 base64 解码
    vmess_bytes = base64.urlsafe_b64decode(vmess_data + '=' * (4 - len(vmess_data) % 4))
    # 将解码后的数据转换为 JSON 格式
    vmess_json = vmess_bytes.decode('utf-8')
    # 解析 JSON 数据
    vmess_dict = json.loads(vmess_json)
    
    return vmess_dict

def restart_v2ray():
    command = 'systemctl restart v2ray'
    if is_docker():
       command = 'supervisorctl restart v2ray'
    try:
      result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
      log("restart v2ray: " + result.stdout.decode('utf-8'))
      sleep(1)
    except Exception as e:
      log("restart v2ray failed: " + str(e))


def update_v2ray(vmess_dict):
    address = vmess_dict['add']
    port = int(vmess_dict['port'])
    id = vmess_dict['id']
    aid = int(vmess_dict['aid'])
    net = vmess_dict['net']
    path = vmess_dict['path']
    config_json = {
            "log": {
              "access": "",
              "error": "",
              "loglevel": "warning"
            },
            "inbounds": [
              {
                "tag": "socks",
                "port": 20810,
                "listen": "0.0.0.0",
                "protocol": "socks",
                "sniffing": {
                  "enabled": True,
                  "destOverride": [
                    "http",
                    "tls"
                  ],
                  "routeOnly": False
                },
                "settings": {
                  "auth": "noauth",
                  "udp": True,
                  "allowTransparent": False
                }
              },
              {
                "tag": "http",
                "port": 20811,
                "listen": "0.0.0.0",
                "protocol": "http",
                "sniffing": {
                  "enabled": True,
                  "destOverride": [
                    "http",
                    "tls"
                  ],
                  "routeOnly": False
                },
                "settings": {
                  "auth": "noauth",
                  "udp": True,
                  "allowTransparent": False
                }
              },
              {
                "port": 20812,
                "protocol": "vmess",
                "settings": {
                  "udp": False,
                  "clients": [
                    {
                      "id": "b831381d-6324-4d53-ad4f-8cda48b30811",
                      "alterId": 0,
                      "email": "t@t.tt"
                    }
                  ],
                  "allowTransparent": False
                },
                "streamSettings": {
                  "network": "ws",
                  "wsSettings": {
                    "path": "/2294-44e2-a528-d9fb1adaa35f.v4..live01.m3u8",
                    "headers": {}
                  }
                }
              }
            ],
            "outbounds": [
              {
                "tag": "proxy",
                "protocol": "vmess",
                "settings": {
                  "vnext": [
                    {
                      "address": address,
                      "port": port,
                      "users": [
                        {
                          "id": id,
                          "alterId": aid,
                          "email": "t@t.tt",
                          "security": "auto"
                        }
                      ]
                    }
                  ]
                },
                "streamSettings": {
                  "network": net,
                  "wsSettings": {
                    "path": path,
                    "headers": {
                    
                    }
                  }
                },
                "mux": {
                  "enabled": True,
                  "concurrency": 8
                }
              },
              {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {
                
                }
              },
              {
                "tag": "block",
                "protocol": "blackhole",
                "settings": {
                  "response": {
                    "type": "http"
                  }
                }
              }
            ],
            "routing": {
              "domainStrategy": "IPIfNonMatch",
              "rules": [
                {
                  "id": "5518802383459979880",
                  "type": "field",
                  "outboundTag": "direct",
                  "domain": [
                    "domain:example-example.com",
                    "domain:example-example2.com"
                  ],
                  "enabled": True
                },
                {
                  "id": "5460952297859702438",
                  "type": "field",
                  "outboundTag": "block",
                  "domain": [
                    "geosite:category-ads-all"
                  ],
                  "enabled": True
                },
                # 绕过限制 
                {
                  "id": "4921452774162550049",
                  "type": "field",
                  "outboundTag": "proxy",
                  "domain": [
                    "domain:bilibili.com",
                    "domain:biliapi.net",
                    "domain:bilivideo.com",
                    "domain:hdslb.com",
                    "domain:douyin.com",
                    "domain:douyincdn.com",
                    "domain:douyinpic.com",
                    "domain:douyinstatic.com",
                    "domain:douyinvod.com",
                    "domain:music.163.com",
                    "domain:music.126.net"
                  ],
                  "enabled": True
                },
                {
                  "id": "5190411545470979683",
                  "type": "field",
                  "outboundTag": "direct",
                  "domain": [
                    "geosite:cn"
                  ],
                  "enabled": True
                },
                {
                  "id": "4921452774162550051",
                  "type": "field",
                  "outboundTag": "direct",
                  "ip": [
                    "geoip:private",
                    "geoip:cn"
                  ],
                  "enabled": True
                },
                {
                  "id": "4921452774162550052",
                  "type": "field",
                  "outboundTag": "direct",
                  "domain": [
                      "domain:ling5821.com"
                  ],
                  "enabled": True
                },
                {
                  "id": "5038322715420606427",
                  "type": "field",
                  "port": "0-65535",
                  "outboundTag": "proxy",
                  "enabled": True
                }
              ]
            }
          }
    config = json.dumps(config_json, indent=4) + "\n"
    
    # write config
    with open(get_config_path(), 'w') as file:
      file.write(config)

    # restart v2ray
    restart_v2ray()

    return test_vmess()

def test_vmess() -> bool:
    proxy_url = get_proxy_url()
    url = 'http://www.google.com'
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36'}
    proxies={'http': proxy_url, 'https': proxy_url}
    try:
      response = requests.get(url, headers=headers, proxies=proxies, timeout=10)
      return response.status_code == 200
    except Exception as ex:
      log("test vmess failed: " + str(ex))
      return False

def main():

    if test_vmess():
       log('proxy available...')
       return

    area_filter = get_area_filter()

    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
    }

    try:
      response = requests.get(get_sub_url(), headers=headers)
      vmess_dict_list = []
      vmess_links = base64.b64decode(response.text).decode('utf-8').split("\n")
      for vmess_link in vmess_links:
        if not vmess_link:
            continue
        vmess_dict = parse_vmess(vmess_link)
        
        if area_filter and re.search(area_filter, str(vmess_dict['ps'])):
            continue
        vmess_dict_list.append(vmess_dict)
    
      for vmess_dict in vmess_dict_list:
          if update_v2ray(vmess_dict):
            log('proxy update success...')
            break
    except Exception as ex:
      log("get sub failed: " + str(ex))
    

if __name__ == "__main__":
    main()
          

