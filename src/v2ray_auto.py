from os import getenv
from time import sleep
from urllib.parse import urlparse, parse_qs, unquote
import requests
import base64
import json
import re
import subprocess
from datetime import datetime


def get_sub_url():
    return getenv("V2RAY_SUB_URL", "")

def get_area_filter():
    return getenv("V2RAY_AREA_FILTER", "新用户|过期|剩余")


def get_proxy_url():
    return getenv("V2RAY_CUR_PROXY", "socks5://127.0.0.1:20810")


def get_config_path():
    return getenv("V2RAY_CONFIG_PATH", "/usr/local/etc/v2ray/config.json")


def is_docker():
    return getenv("V2RAY_IN_DOCKER", "false") == "true"


def log(content):
    formatted_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(formatted_time + " " + content)


def safe_b64decode(data: str) -> bytes:
    """自动补全 base64 padding"""
    data += "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data)


def parse_vmess(link: str):
    """
    vmess://base64(json)
    """
    vmess_data = link.split("://", 1)[1]

    vmess_json = safe_b64decode(vmess_data).decode("utf-8")
    vmess_dict = json.loads(vmess_json)

    return {
        **vmess_dict,
        "type": "vmess",
        "name": vmess_dict.get("ps"),
        "server": vmess_dict.get("add"),
        "port": int(vmess_dict.get("port")),
    }


def parse_hysteria2(link: str):
    """
    hysteria2://password@host:port/?sni=xxx#name
    """

    parsed = urlparse(link)

    password = parsed.username
    host = parsed.hostname
    port = parsed.port

    query = parse_qs(parsed.query)

    return {
        "type": "hysteria2",
        "server": host,
        "port": port,
        "password": password,
        "sni": query.get("sni", [None])[0],
        "obfs": query.get("obfs", [None])[0],
        "obfs-password": query.get("obfs-password", [None])[0],
        "alpn": query.get("alpn", [None])[0],
        "name": unquote(parsed.fragment) if parsed.fragment else None,
    }


def parse_vless_or_trojan(link: str, protocol: str):
    """
    vless://uuid@host:port?...#name
    trojan://password@host:port?...#name
    """

    parsed = urlparse(link)

    query = parse_qs(parsed.query)

    return {
        "type": protocol,
        "server": parsed.hostname,
        "port": parsed.port,
        "id": parsed.username,
        "name": unquote(parsed.fragment) if parsed.fragment else None,
        "query": query,
    }


def parse_ss(link: str):
    """
    ss://base64(method:password@host:port)#name
    """

    content = link.split("://", 1)[1]

    if "#" in content:
        content, name = content.split("#", 1)
        name = unquote(name)
    else:
        name = None

    decoded = safe_b64decode(content).decode("utf-8")

    method_password, server_part = decoded.split("@")
    method, password = method_password.split(":")

    host, port = server_part.split(":")

    return {
        "type": "shadowsocks",
        "server": host,
        "port": int(port),
        "method": method,
        "password": password,
        "name": name,
    }


def parse_proxy_link(link: str):
    """
    自动识别协议并解析
    """

    if link.startswith("vmess://"):
        return parse_vmess(link)

    elif link.startswith("hysteria2://"):
        return parse_hysteria2(link)

    elif link.startswith("vless://"):
        return parse_vless_or_trojan(link, "vless")

    elif link.startswith("trojan://"):
        return parse_vless_or_trojan(link, "trojan")

    elif link.startswith("ss://"):
        return parse_ss(link)

    else:
        raise ValueError(f"Unsupported protocol: {link}")


def build_hysteria2_outbound(proxy_dict):
    server = proxy_dict["server"]
    port = int(proxy_dict["port"])
    password = proxy_dict["password"]
    sni = proxy_dict.get("sni")
    alpn = proxy_dict.get("alpn")
    obfs = proxy_dict.get("obfs")
    obfs_password = proxy_dict.get("obfs-password")
    return {
        "tag": "proxy",
        "protocol": "hysteria",
        "settings": {"address": server, "port": port, "version": 2},
        "streamSettings": {
            "network": "hysteria",
            "security": "tls",
            "tlsSettings": {
                "allowInsecure": False,
                "serverName": sni,
                "alpn": [alpn],
            },
            "hysteriaSettings": {
                "version": 2,
                "auth": password,
            },
            "finalmask": {
                "udp": [{"type": obfs, "settings": {"password": obfs_password}}],
                "quicParams": {
                    "congestion": "brutal",
                    "brutalUp": "100mbps",
                    "brutalDown": "100mbps",
                },
            },
        },
        "mux": {"enabled": False},
    }


def build_vmess_outbound(proxy_dict):
    server = proxy_dict["server"]
    port = int(proxy_dict["port"])
    id = proxy_dict["id"]
    aid = int(proxy_dict["aid"])
    net = proxy_dict["net"]
    path = proxy_dict["path"]

    return {
        "tag": "proxy",
        "protocol": "vmess",
        "settings": {
            "vnext": [
                {
                    "address": server,
                    "port": port,
                    "users": [
                        {
                            "id": id,
                            "alterId": aid,
                            "email": "t@t.tt",
                            "security": "auto",
                        }
                    ],
                }
            ]
        },
        "streamSettings": {
            "network": net,
            "wsSettings": {"path": path, "headers": {}},
        },
        "mux": {"enabled": True, "concurrency": 8},
    }


def build_v2ray_outbounds(proxy_dict):
    outbounds = []
    if proxy_dict["type"] == "vmess":
        outbounds.append(build_vmess_outbound(proxy_dict))
    elif proxy_dict["type"] == "hysteria2":
        outbounds.append(build_hysteria2_outbound(proxy_dict))
    else:
        raise ValueError(f"Unsupported protocol type: {proxy_dict['type']}")
    outbounds.append({"tag": "direct", "protocol": "freedom"})
    outbounds.append({"tag": "block", "protocol": "blackhole"})
    return outbounds


def restart_v2ray():
    # 重新启动 v2ray/xray 以应用新配置
    command = "systemctl restart v2ray"
    if is_docker():
        command = "supervisorctl restart v2ray"
    try:
        result = subprocess.run(
            command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        log("restart v2ray(xray): " + result.stdout.decode("utf-8"))
        sleep(1)
    except Exception as e:
        log("restart v2ray(xray) failed: " + str(e))


def update_v2ray(proxy_dict):
    outbounds = build_v2ray_outbounds(proxy_dict)

    config_json = {
        "log": {"access": "", "error": "", "loglevel": "warning"},
        "dns": {"servers": ["1.1.1.1", "8.8.8.8"]},
        "inbounds": [
            {
                "tag": "socks",
                "port": 20810,
                "listen": "0.0.0.0",
                "protocol": "socks",
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls"],
                    "routeOnly": False,
                },
                "settings": {"auth": "noauth", "udp": True, "allowTransparent": False},
            },
            {
                "tag": "http",
                "port": 20811,
                "listen": "0.0.0.0",
                "protocol": "http",
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls"],
                    "routeOnly": False,
                },
                "settings": {"auth": "noauth", "udp": True, "allowTransparent": False},
            },
            {
                "port": 20812,
                "protocol": "vmess",
                "settings": {
                    "udp": True,
                    "clients": [
                        {
                            "id": "b831381d-6324-4d53-ad4f-8cda48b30811",
                            "alterId": 0,
                        }
                    ],
                    "allowTransparent": False,
                },
                "streamSettings": {"network": "tcp"},
            },
        ],
        "outbounds": [],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {
                    "id": "5518802383459979880",
                    "type": "field",
                    "outboundTag": "direct",
                    "domain": [
                        "domain:example-example.com",
                        "domain:example-example2.com",
                    ],
                    "enabled": True,
                },
                {
                    "id": "5460952297859702438",
                    "type": "field",
                    "outboundTag": "block",
                    "domain": ["geosite:category-ads-all"],
                    "enabled": True,
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
                        "domain:music.126.net",
                        "domain:kuwo.cn",
                    ],
                    "enabled": True,
                },
                {
                    "type": "field",
                    "outboundTag": "proxy",
                    "domain": ["geosite:google"],
                    "enabled": True,
                },
                {
                    "type": "field",
                    "outboundTag": "direct",
                    "ip": ["geoip:private"],
                    "enabled": True,
                },
                {
                    "type": "field",
                    "outboundTag": "direct",
                    "domain": ["geosite:private"],
                    "enabled": True,
                },
                {
                    "type": "field",
                    "outboundTag": "direct",
                    "ip": [
                        "223.5.5.5",
                        "223.6.6.6",
                        "2400:3200::1",
                        "2400:3200:baba::1",
                        "119.29.29.29",
                        "1.12.12.12",
                        "120.53.53.53",
                        "2402:4e00::",
                        "2402:4e00:1::",
                        "180.76.76.76",
                        "2400:da00::6666",
                        "114.114.114.114",
                        "114.114.115.115",
                        "114.114.114.119",
                        "114.114.115.119",
                        "114.114.114.110",
                        "114.114.115.110",
                        "180.184.1.1",
                        "180.184.2.2",
                        "101.226.4.6",
                        "218.30.118.6",
                        "123.125.81.6",
                        "140.207.198.6",
                        "1.2.4.8",
                        "210.2.4.8",
                        "52.80.66.66",
                        "117.50.22.22",
                        "2400:7fc0:849e:200::4",
                        "2404:c2c0:85d8:901::4",
                        "117.50.10.10",
                        "52.80.52.52",
                        "2400:7fc0:849e:200::8",
                        "2404:c2c0:85d8:901::8",
                        "117.50.60.30",
                        "52.80.60.30",
                    ],
                    "enabled": True,
                },
                {
                    "type": "field",
                    "outboundTag": "direct",
                    "domain": [
                        "domain:alidns.com",
                        "domain:doh.pub",
                        "domain:dot.pub",
                        "domain:360.cn",
                        "domain:onedns.net",
                        "domain:todesk.com",
                        "domain:oray.com",
                        "domain:oray.net",
                        "domain:yhgfb-cn-static.com",
                    ],
                    "enabled": True,
                },
                {
                    "type": "field",
                    "outboundTag": "direct",
                    "ip": ["geoip:cn"],
                    "enabled": True,
                },
                {
                    "type": "field",
                    "outboundTag": "direct",
                    "domain": ["geosite:cn"],
                    "enabled": True,
                },
                {
                    "id": "4921452774162550052",
                    "type": "field",
                    "outboundTag": "direct",
                    "domain": ["domain:ling5821.com"],
                    "enabled": True,
                },
            ],
        },
    }
    config_json["outbounds"] = outbounds
    config = json.dumps(config_json, indent=4) + "\n"

    # write config
    with open(get_config_path(), "w") as file:
        file.write(config)

    # restart v2ray
    restart_v2ray()

    return test_proxy()


def test_proxy() -> bool:
    proxy_url = get_proxy_url()
    url = "http://www.google.com"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
    }
    proxies = {"http": proxy_url, "https": proxy_url}
    try:
        response = requests.get(url, headers=headers, proxies=proxies, timeout=10)
        return response.status_code == 200
    except Exception as ex:
        log("test proxy failed: " + str(ex))
        return False


def main():

    if test_proxy():
        log("proxy available...")
        return

    area_filter = get_area_filter()

    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "User-Agent": "V2rayNG",
    }

    try:
        response = requests.get(get_sub_url(), headers=headers)
        proxy_dict_list = []
        sub_links = base64.b64decode(response.text).decode("utf-8").split("\n")
        for sub_link in sub_links:
            if not sub_link:
                continue
            proxy_dict = parse_proxy_link(sub_link)

            if area_filter and re.search(area_filter, str(proxy_dict["name"])):
                continue
            proxy_dict_list.append(proxy_dict)

        if not proxy_dict_list:
            log("sub response is empty or no available proxy links found...")
            return

        for proxy_dict in proxy_dict_list:
            if update_v2ray(proxy_dict):
                log("proxy update success...")
                break
    except Exception as ex:
        log("get sub failed: " + str(ex))


if __name__ == "__main__":
    main()
