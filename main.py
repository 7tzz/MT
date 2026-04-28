# -*- coding: utf-8 -*-
"""
MT论坛自动签到 (bbs.binmt.cc) —— Cookie 复用版 / 绕过阿里云 ESA JS 盾

背景
----
站点在「登录页 / 论坛列表页」等路径启用了阿里云 ESA(WAF) 的 JS 人机验证:
requests 不执行 JS, 只能拿到 challenge 空壳(HTTP 200 但没有 formhash), 因此
"每次走密码登录 + 从登录弹窗抓 formhash" 的旧逻辑必然失败。

但「签到页 k_misign-sign.html」与「签到插件 plugin.php?id=k_misign:sign」这两条
路径不在 WAF 自定义规则内, 用普通 requests 也能拿到真实页面。正确做法是:
  1) 用【浏览器登录一次】导出的登录 Cookie 复用登录态(纯 requests 已无法自动登录);
  2) 访问签到页, 从签到按钮 #JD_sign 的 href 里取 formhash;
  3) 请求 plugin.php?id=k_misign:sign&operation=qiandao&formhash=xxx 完成签到;
  4) 回查签到状态。全程不碰被 JS 盾拦截的登录路径。

配置来源(优先级: 进程环境变量 > .env 文件 > 默认值)
-----------------------------------------------
MT_COOKIES    (推荐/最稳) 浏览器登录后导出的 Cookie。支持多账号/JSON, 见 README。
MT_ACCOUNTS   (备选) 账号密码登录, 每行 `用户名:密码`, 多账号每行一个。
              ⚠️ 论坛登录接口已被阿里云 ESA JS 盾保护, 从数据中心 IP(云服务器/青龙/GitHub)发起
              的登录大概率被挑战而失败; 仅当出口 IP 未被挑战时才成功。故 Cookie 模式更可靠。
ENABLE_PROXY  (可选) true 时启用代理兜底, 默认关闭(直连)。
PROXY_SOURCES(可选) 逗号分隔的代理列表 txt 直链, 默认用 klaas8/MT 的 verify/ips。
WECHAT_WEBHOOK (可选) 企业微信群机器人 Webhook 地址(含 key); 设了就优先用它推送,
               不受「API 调用 IP 白名单」限制, 适合 GitHub 托管 runner。
WECHAT_CORPID / WECHAT_CORPSECRET / WECHAT_AGENTID (可选) 企业微信自建应用推送(回退用, 受 IP 白名单限制)。
WECHAT_TOUSER (可选) 自建应用接收人 userid, 默认 @all(发给应用可见所有人)。
REQ_TIMEOUT / MAX_RETRY / MAX_PROXIES (可选) 运行时调参。

Discuz 登录态主要由 <前缀>_auth + <前缀>_saltkey 决定; 最稳妥是把整条 Cookie 头粘贴进来。
"""
from __future__ import annotations

import os
import re
import sys
import time
import json
import random
import ipaddress
from dataclasses import dataclass, field
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

import requests
from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
# 日志: 统一走 logging, 流式输出到 stdout(GitHub Actions 直接捕获)
# ---------------------------------------------------------------------------
import logging

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("mt-sign")


# ---------------------------------------------------------------------------
# 本地 .env 支持(可选, 仅便利本地调试; 在 CI 中由 Secrets 注入, 不受影响)
# 用 setdefault 避免覆盖已存在的进程环境变量。
# ---------------------------------------------------------------------------
def load_dotenv(path: str = ".env") -> None:
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key, value = key.strip(), value.strip().strip('"').strip("'")
            os.environ.setdefault(key, value)


# ---------------------------------------------------------------------------
# 配置: 集中读取一次, 全程序共享, 告别散落的 os.environ.get
# ---------------------------------------------------------------------------
DEFAULT_PROXY_SOURCES = [
    "https://raw.githubusercontent.com/klaas8/MT/main/src/verify.txt",
    "https://raw.githubusercontent.com/klaas8/MT/main/src/ips.txt",
]

JS_CHALLENGE_MARKERS = ("var arg1=", "__jsl", "jsl_clearance")  # 命中即视为被 WAF 拦截


@dataclass
class Config:
    base: str = "https://bbs.binmt.cc"
    cookies: str = ""
    enable_proxy: bool = False
    proxy_sources: list[str] = field(default_factory=list)
    req_timeout: int = 20
    max_retry: int = 3
    max_proxies: int = 12
    wechat_corpid: str = ""
    wechat_corpsecret: str = ""
    wechat_agentid: str = ""
    wechat_touser: str = "@all"
    wechat_webhook: str = ""
    mt_accounts: str = ""

    @classmethod
    def from_env(cls) -> "Config":
        raw_sources = (os.environ.get("PROXY_SOURCES", "") or "").strip()
        sources = [s.strip() for s in raw_sources.split(",") if s.strip()] or list(
            DEFAULT_PROXY_SOURCES
        )
        return cls(
            cookies=(os.environ.get("MT_COOKIES", "") or "").strip(),
            enable_proxy=os.environ.get("ENABLE_PROXY", "").lower()
            in ("1", "true", "yes"),
            proxy_sources=sources,
            req_timeout=int(os.environ.get("REQ_TIMEOUT", "20")),
            max_retry=int(os.environ.get("MAX_RETRY", "3")),
            max_proxies=int(os.environ.get("MAX_PROXIES", "12")),
            wechat_corpid=os.environ.get("WECHAT_CORPID", "") or "",
            wechat_corpsecret=os.environ.get("WECHAT_CORPSECRET", "") or "",
            wechat_agentid=os.environ.get("WECHAT_AGENTID", "") or "",
            wechat_touser=os.environ.get("WECHAT_TOUSER", "@all") or "@all",
            wechat_webhook=os.environ.get("WECHAT_WEBHOOK", "") or "",
            mt_accounts=os.environ.get("MT_ACCOUNTS", "") or "",
        )


# 派生 URL(基于 cfg.base, 便于将来改域名)
def sign_page_url(cfg: Config) -> str:
    return f"{cfg.base}/k_misign-sign.html"


def plugin_sign_url(cfg: Config, formhash: str) -> str:
    return (
        f"{cfg.base}/plugin.php?id=k_misign:sign&operation=qiandao"
        f"&formhash={formhash}&format=text"
    )


HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "Connection": "keep-alive",
}

# 关掉 verify=False 的告警(部分代理链路证书不全)
try:
    from urllib3.exceptions import InsecureRequestWarning
    import urllib3

    urllib3.disable_warnings(InsecureRequestWarning)
except Exception:
    pass


# ---------------------------------------------------------------------------
# 企业微信推送（两种通道，按配置自动选择）
#
# 通道 A —— 群机器人 Webhook（推荐，不受「API 调用 IP 白名单」限制）
#   在企业微信群聊里「添加群机器人」拿到 webhook 地址(含 key), 直接 POST 即可,
#   不需要 corpid/agentid/secret, 也不受 GitHub 托管 runner 出口 IP 不在白名单的 60020 拦截。
#   文档: https://developer.work.weixin.qq.com/document/path/91770
#
# 通道 B —— 自建应用 message/send（需 corpid/agentid/secret, 受 IP 白名单限制）
#   流程: 1) corpid+corpsecret 换 access_token  2) message/send 发应用消息
#   文档: https://developer.work.weixin.qq.com/document/path/90236
# ---------------------------------------------------------------------------
def wechat_webhook_push(webhook: str, content: str) -> bool:
    """通道 A: 企业微信群机器人 Webhook 推送（纯文本 text，微信里也能正常显示）。"""
    if not webhook:
        return False
    try:
        payload = {"msgtype": "text", "text": {"content": content}}
        resp = requests.post(webhook, json=payload, timeout=10)
        rd = resp.json()
        if rd.get("errcode", -1) == 0:
            log.info("企业微信群机器人推送成功")
            return True
        log.warning(f"企业微信群机器人推送失败: {rd}")
        return False
    except Exception as e:
        log.warning(f"企业微信群机器人推送异常: {e}")
        return False


def wechat_push(cfg: Config, content: str) -> bool:
    """通道 B: 企业微信自建应用推送(受 API 调用 IP 白名单限制, 仅白名单内/自托管 runner 可用)。"""
    if not (cfg.wechat_corpid and cfg.wechat_corpsecret and cfg.wechat_agentid):
        log.warning("未配置 WECHAT_CORPID/WECHAT_CORPSECRET/WECHAT_AGENTID, 跳过企业微信自建应用推送")
        return False
    try:
        # 1) 获取 access_token(每日限额 2000 次, 单次运行取一次即可)
        r = requests.get(
            "https://qyapi.weixin.qq.com/cgi-bin/gettoken",
            params={"corpid": cfg.wechat_corpid, "corpsecret": cfg.wechat_corpsecret},
            timeout=10,
        )
        data = r.json()
        if data.get("errcode", 0) != 0:
            log.warning(f"企业微信获取 access_token 失败: {data}")
            return False
        token = data["access_token"]

        # 2) 发送 纯文本 应用消息（text，微信插件镜像后也能正常显示）
        payload = {
            "touser": cfg.wechat_touser,
            "msgtype": "text",
            "agentid": int(cfg.wechat_agentid),
            "text": {"content": content},
        }
        resp = requests.post(
            "https://qyapi.weixin.qq.com/cgi-bin/message/send",
            params={"access_token": token},
            json=payload,
            timeout=10,
        )
        rd = resp.json()
        if rd.get("errcode", 0) == 0:
            log.info("企业微信自建应用推送成功")
            return True
        log.warning(f"企业微信自建应用推送失败: {rd}")
        return False
    except Exception as e:
        log.warning(f"企业微信自建应用推送异常: {e}")
        return False


def push_result(cfg: Config, content: str) -> bool:
    """统一推送入口: 优先群机器人 Webhook, 否则回退自建应用。"""
    if cfg.wechat_webhook:
        return wechat_webhook_push(cfg.wechat_webhook, content)
    return wechat_push(cfg, content)


# ---------------------------------------------------------------------------
# Cookie 解析
# ---------------------------------------------------------------------------
def parse_cookie_string(blob: str) -> dict:
    """把浏览器 'Cookie: a=1; b=2' 头解析成 dict(剔除属性类字段)。"""
    cookies: dict[str, str] = {}
    skip = {"path", "domain", "expires", "max-age", "httponly", "secure", "samesite"}
    for pair in blob.split(";"):
        pair = pair.strip()
        if not pair or "=" not in pair:
            continue
        k, v = pair.split("=", 1)
        k, v = k.strip(), v.strip()
        if k and k.lower() not in skip:
            cookies[k] = v
    return cookies


def load_accounts(cfg: Config) -> list[tuple[str, dict]]:
    """
    解析账号, 返回 [(label, payload), ...], payload 含 mode 字段:
      - mode=="pwd" : {"mode":"pwd","user":...,"pwd":...}  (账号密码登录, MT_ACCOUNTS)
      - mode=="cookie": {"mode":"cookie","cookies":{...}}  (Cookie 复用, MT_COOKIES, 推荐)

    模式自动选择: 设了 MT_ACCOUNTS 优先走密码登录; 否则回退到 MT_COOKIES。
    """
    # 密码模式优先
    if cfg.mt_accounts.strip():
        accounts: list[tuple[str, dict]] = []
        for line in (l.strip() for l in cfg.mt_accounts.splitlines() if l.strip()):
            if ":" not in line:
                log.warning(f"账号行缺少 ':' 分隔, 跳过: {line[:16]}...")
                continue
            user, pwd = line.split(":", 1)
            user, pwd = user.strip(), pwd.strip()
            if not user or not pwd:
                log.warning(f"账号/密码为空, 跳过: {line[:16]}...")
                continue
            accounts.append((user, {"mode": "pwd", "user": user, "pwd": pwd}))
        if accounts:
            return accounts
        log.warning("MT_ACCOUNTS 已设置但无有效账号, 回退尝试 MT_COOKIES")

    # Cookie 模式
    raw = cfg.cookies
    if not raw:
        log.error("未设置 MT_COOKIES 或 MT_ACCOUNTS, 无法运行。")
        sys.exit(1)

    accounts = []
    if raw.startswith("{"):
        try:
            data = json.loads(raw)
            for i, (label, val) in enumerate(data.items()):
                ck = val if isinstance(val, dict) else parse_cookie_string(str(val))
                accounts.append((label or f"账号{i + 1}", {"mode": "cookie", "cookies": ck}))
        except Exception as e:
            log.error(f"MT_COOKIES 是 JSON 但解析失败: {e}")
            sys.exit(1)
    else:
        for i, line in enumerate(l.strip() for l in raw.splitlines() if l.strip()):
            label = f"账号{i + 1}"
            if "::" in line:
                label, line = line.split("::", 1)
            accounts.append(
                (label.strip() or label, {"mode": "cookie", "cookies": parse_cookie_string(line.strip())})
            )

    for label, acc in accounts:
        ck = acc["cookies"]
        if not any(k.endswith(("_auth", "_saltkey")) for k in ck):
            log.warning(f"[{label}] Cookie 里没看到 _auth/_saltkey, 可能未登录或前缀不符, 仍尝试")
    return accounts


def _re_first(html: str, pattern: str) -> str:
    """从 html 里取第一个正则捕获组, 去空格; 没命中返回空串。"""
    m = re.search(pattern, html, re.IGNORECASE | re.UNICODE)
    return m.group(1).strip() if m and m.group(1) else ""


def login_session(user: str, pwd: str, proxy: Optional[str], cfg: Config) -> tuple[Optional[requests.Session], str]:
    """
    密码登录模式: 通过 Discuz ajax 登录接口拿登录态。
    返回 (session, err): err=="" 表示成功拿到已登录 session; 否则 err 为失败原因。
    ⚠️ 该登录接口已被阿里云 ESA JS 盾保护, 从数据中心 IP(云服务器/青龙/GitHub)发起大概率被
    挑战而拿不到 formhash, 此时 err 含 'JS挑战'; 仅当出口 IP 未被挑战时才成功。
    """
    s = requests.Session()
    s.headers.update(HEADERS)
    s.headers["Referer"] = f"{cfg.base}/"
    if proxy:
        s.proxies = {"http": f"http://{proxy}", "https": f"http://{proxy}"}
    try:
        r = s.get(
            f"{cfg.base}/member.php?mod=logging&action=login&infloat=yes&handlekey=login"
            f"&inajax=1&ajaxtarget=fwin_content_login",
            timeout=cfg.req_timeout, verify=False,
        )
    except Exception as e:
        return None, f"登录页请求异常: {e}"
    if is_blocked(r.text):
        return None, "登录页命中JS挑战(ESA WAF), 该IP被拦"
    loginhash = _re_first(r.text, r"loginhash.*?=(.*?)[\"']>")
    formhash = _re_first(r.text, r"formhash[\"'].*?value=[\"'](.*?)[\"'].*?/>")
    if not formhash:
        return None, "登录页未取到formhash(可能被WAF拦)"
    data = {
        "formhash": formhash,
        "referer": f"{cfg.base}/k_misign-sign.html",
        "fastloginfield": "username",
        "username": user, "password": pwd,
        "questionid": "0", "answer": "", "agreebbrule": "",
    }
    try:
        rr = s.post(
            f"{cfg.base}/member.php?mod=logging&action=login&loginsubmit=yes"
            f"&handlekey=login&loginhash={loginhash}&inajax=1",
            data=data, timeout=cfg.req_timeout, verify=False,
        )
    except Exception as e:
        return None, f"登录POST异常: {e}"
    if "失败" in rr.text:
        return None, "密码错误"
    return s, ""


# ---------------------------------------------------------------------------
# 代理池(可选)
# ---------------------------------------------------------------------------
def _valid_ip_port(ip: str, port: str) -> bool:
    try:
        if ipaddress.ip_address(ip).is_multicast or ipaddress.ip_address(ip).is_unspecified:
            return False
    except ValueError:
        return False
    return 1 <= int(port) <= 65535


def is_blocked(html: str) -> bool:
    """内容是否命中 JS 挑战/提示信息壳(用于鉴别假代理与 WAF 拦截)。"""
    return any(m in html for m in JS_CHALLENGE_MARKERS)


def validate_proxy(proxy: str, cfg: Config) -> tuple[str, bool, int]:
    """
    验证代理: 必须能拿到【真实的签到页】(含 k_misign 且不含 JS 挑战),
    而不是被 WAF 用 200 空壳骗过(旧 verify_proxy 的 bug)。
    返回 (proxy, 是否可用, 耗时ms)。
    """
    proxies = {"http": f"http://{proxy}", "https": f"http://{proxy}"}
    t0 = time.time()
    try:
        r = requests.get(sign_page_url(cfg), headers=HEADERS, proxies=proxies,
                         timeout=cfg.req_timeout, verify=False)
        good = r.ok and ("k_misign" in r.text) and not is_blocked(r.text)
        return proxy, good, int((time.time() - t0) * 1000)
    except Exception as e:
        log.warning(f"   代理不可达 {proxy}: {type(e).__name__}")
        return proxy, False, -1


def load_proxies(cfg: Config) -> list[str]:
    """从代理源拉取候选, 用真实签到页并发校验, 返回按速度排序的前 N 个可用代理。"""
    cand: set[str] = set()
    for url in cfg.proxy_sources:
        try:
            resp = requests.get(url, timeout=15, headers={"User-Agent": HEADERS["User-Agent"]})
            if resp.status_code != 200:
                log.warning(f"代理源下载非200 {url}: HTTP {resp.status_code}")
                continue
            n0 = len(cand)
            for line in resp.text.splitlines():
                ip = line.strip()
                if ":" not in ip:
                    continue
                a, b = ip.split(":", 1)
                if _valid_ip_port(a, b):
                    cand.add(ip)
            log.info(f"代理源载入 {len(cand) - n0} 个: {url}")
        except Exception as e:
            log.warning(f"代理源下载失败 {url}: {e}")

    log.info(f"候选代理 {len(cand)} 个, 正在按真实签到页校验...")
    alive: list[tuple[str, int]] = []
    with ThreadPoolExecutor(max_workers=30) as ex:
        for proxy, ok, ms in [f.result() for f in as_completed(
                [ex.submit(validate_proxy, p, cfg) for p in cand])]:
            if ok:
                alive.append((proxy, ms))
    alive.sort(key=lambda x: x[1])
    log.info(f"可用代理(真实通过校验): {len(alive)} 个")
    return [p for p, _ in alive[: cfg.max_proxies]]


# ---------------------------------------------------------------------------
# 核心签到
# ---------------------------------------------------------------------------
def build_session(cookies: dict, proxy: Optional[str] = None) -> requests.Session:
    s = requests.Session()
    s.headers.update(HEADERS)
    s.headers["Referer"] = "https://bbs.binmt.cc/"
    for k, v in cookies.items():
        s.cookies.set(k, v)
    if proxy:
        s.proxies = {"http": f"http://{proxy}", "https": f"http://{proxy}"}
    return s


def sign_once(s: requests.Session, cfg: Config) -> tuple[str, str]:
    """
    对已经建好(已登录)的 session 做一次签到尝试。
    返回 (status, detail): status ∈ {signed, done, need_cookie, failed, blocked}
    """
    # 1) 打开签到页, 判断登录态 & 取 formhash
    fh: Optional[str] = None
    for _ in range(cfg.max_retry):
        try:
            r = s.get(sign_page_url(cfg), timeout=cfg.req_timeout, verify=False)
        except Exception as e:
            log.warning(f"  签到页请求异常: {e}")
            time.sleep(1.5 + random.random())
            continue

        if is_blocked(r.text):
            return ("blocked", "签到页命中JS挑战(该IP被WAF拦), 换代理或直连")

        soup = BeautifulSoup(r.text, "html.parser")

        # 已签到?
        if soup.find("span", class_="btnvisted") or "今日已签" in r.text:
            return ("signed", "今日已签到")

        # 未登录(提示信息页 / 无签到按钮)?
        btn = soup.find("a", id="JD_sign")
        if not btn:
            if "提示信息" in r.text or "登录" in r.text:
                return ("need_cookie", "未检测到登录态(Cookie无效/过期或密码错误), 请重新设置")
            inp = soup.find("input", {"name": "formhash"})
            fh = inp["value"] if inp and inp.has_attr("value") else None
        else:
            m = re.search(r"formhash=([a-f0-9]+)", btn.get("href", ""))
            fh = m.group(1) if m else None

        if fh:
            break
        time.sleep(1.5 + random.random())

    if not fh:
        return ("failed", "未能获取签到formhash")

    # 2) 触发签到
    url = plugin_sign_url(cfg, fh)
    last = ""
    for _ in range(cfg.max_retry):
        try:
            rr = s.get(url, timeout=cfg.req_timeout, verify=False,
                       headers={"X-Requested-With": "XMLHttpRequest"})
            last = rr.text[:200]
            if rr.status_code == 200 and ("已签" in rr.text or "成功" in rr.text or rr.text.strip() == ""):
                time.sleep(1.2 + random.random())
                chk = s.get(sign_page_url(cfg), timeout=cfg.req_timeout, verify=False)
                if "今日已签" in chk.text or BeautifulSoup(chk.text, "html.parser").find(
                        "span", class_="btnvisted"):
                    return ("done", f"签到成功 (formhash={fh})")
                return ("done", f"签到请求已提交(formhash={fh})")
        except Exception as e:
            log.warning(f"  签到请求异常: {e}")
        time.sleep(1.5 + random.random())
    return ("failed", f"签到未确认: {last}")


def do_account(label: str, acc: dict, proxies: list[str], cfg: Config) -> tuple[bool, str]:
    """先直连, 再逐个代理兜底; 返回 (是否成功, 详情)。"""
    if acc.get("mode") == "pwd":
        builder = lambda p: login_session(acc["user"], acc["pwd"], p, cfg)
    else:
        builder = lambda p: (build_session(acc["cookies"], p), "")

    channels = [None] + list(proxies)
    for proxy in channels:
        tag = "直连" if proxy is None else f"代理 {proxy}"
        try:
            s, err = builder(proxy)
        except Exception as e:
            log.warning(f"[{label}] {tag} 通道构建异常: {e}")
            s, err = None, "fail"
        if s is None:
            if err == "密码错误":
                log.error(f"[{label}] 密码错误, 登录失败")
                return False, "密码错误"
            log.warning(f"[{label}] {tag} 登录/准备失败: {err}")
            if proxy is None and not proxies:
                break
            continue
        try:
            status, detail = sign_once(s, cfg)
        except Exception as e:
            log.warning(f"[{label}] {tag} 签到异常: {e}")
            status, detail = "failed", str(e)

        if status in ("signed", "done"):
            log.info(f"[{label}] {tag} => {detail}")
            return True, detail
        if status == "need_cookie":
            log.error(f"[{label}] {detail}")  # 换IP也没用, 直接判失败
            return False, detail
        log.warning(f"[{label}] {tag} => {status}: {detail}")
        if proxy is None and not proxies:
            break  # 无代理兜底可换, 避免反复撞同一个直连
    return False, "所有通道均失败"


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def main() -> None:
    load_dotenv()
    cfg = Config.from_env()

    log.info("===== MT论坛签到开始 =====")
    accounts = load_accounts(cfg)
    mode = "密码登录" if accounts and accounts[0][1].get("mode") == "pwd" else "Cookie复用"
    log.info(f"模式: {mode} | 共 {len(accounts)} 个账号")

    proxies: list[str] = []
    if cfg.enable_proxy:
        try:
            proxies = load_proxies(cfg)
        except Exception as e:
            log.warning(f"代理加载失败, 退回直连: {e}")

    ok_list, fail_list = [], []
    for i, (label, acc) in enumerate(accounts):
        success, detail = do_account(label, acc, proxies, cfg)
        (ok_list if success else fail_list).append(f"{label}({detail})")
        if i < len(accounts) - 1:
            time.sleep(3)

    log.info("===== 完成, 推送结果 =====")
    all_ok = not fail_list
    content = (
        f"MT论坛签到 {'✓ 成功' if all_ok else '✗ 有失败'}\n"
        f"日期: {datetime.now():%Y-%m-%d}\n"
        f"成功 ({len(ok_list)}): {', '.join(ok_list) or '无'}\n"
        f"失败 ({len(fail_list)}): {', '.join(fail_list) or '无'}"
    )
    push_result(cfg, content)

    if fail_list:
        sys.exit(1)


if __name__ == "__main__":
    main()
