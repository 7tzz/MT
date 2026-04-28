# MT论坛自动签到

MT管理器论坛（[bbs.binmt.cc](https://bbs.binmt.cc)）每日自动签到脚本，支持 GitHub Actions、本机、青龙面板三种运行方式，签到结果通过企业微信群机器人推送。

## 功能

- 多账号签到：一行一个 Cookie，或 JSON 映射，可带 `别名::` 前缀
- 浏览器导出的登录 Cookie 复用登录态
- 代理兜底：网络受限时自动拉取并校验可用代理后切换
- 企业微信群机器人 Webhook 推送签到结果
- 支持 GitHub Actions / 本机 / 青龙面板运行

## 配置项

脚本只认环境变量（GitHub Secrets / 青龙环境变量 / 本机 export / `.env`），优先级：**进程环境变量 > `.env` 文件 > 默认值**。

| 变量 | 必填 | 说明 |
|------|------|------|
| `MT_COOKIES` | ✅ | 浏览器导出的整条 Cookie。多账号每行一个；或 JSON `{"别名":"整串cookie"}`；可加 `别名::` 前缀 |
| `MT_ACCOUNTS` | ❌ | 账号密码登录，每行 `用户名:密码`，多账号每行一个 |
| `ENABLE_PROXY` | ❌ | 设为 `true` 启用代理兜底，默认关闭直连 |
| `PROXY_SOURCES` | ❌ | 逗号分隔的代理列表 txt 直链；留空则用默认代理源 |
| `WECHAT_WEBHOOK` | ❌ | 企业微信群机器人 Webhook 地址（含 `key`），推荐 |
| `WECHAT_CORPID` | ❌ | 企业微信自建应用企业 ID（回退推送用） |
| `WECHAT_CORPSECRET` | ❌ | 企业微信自建应用 Secret（回退推送用） |
| `WECHAT_AGENTID` | ❌ | 企业微信自建应用 AgentId（回退推送用） |
| `WECHAT_TOUSER` | ❌ | 自建应用接收人 userid，默认 `@all` |
| `REQ_TIMEOUT` | ❌ | 单次请求超时秒数，默认 `20` |
| `MAX_RETRY` | ❌ | 单通道重试次数，默认 `3` |
| `MAX_PROXIES` | ❌ | 校验后保留的最快代理数量，默认 `12` |

- **登录模式**：设了 `MT_ACCOUNTS` 优先走账号密码登录；否则用 `MT_COOKIES` Cookie 复用（推荐）。
- **推送策略**：配置了 `WECHAT_WEBHOOK` 优先走群机器人 Webhook；未配置时回退到自建应用 `message/send`。

## 导出登录 Cookie

1. 用电脑浏览器打开 `https://bbs.binmt.cc` 并登录（勾选「自动登录/记住我」，Cookie 可维持约一年）。
2. 按 F12 → **Network(网络)** → 刷新页面 → 点任意一条 `bbs.binmt.cc` 请求。
3. 在 **Request Headers** 里找到整行 `Cookie:`，把整串内容复制下来（关键项是 `_auth` 和 `_saltkey`，整串粘贴最稳）。

## 部署到 GitHub Actions

1. 在仓库 **Settings → Secrets and variables → Actions → New repository secret** 中配置：
   - `MT_COOKIES`：上面复制的整串 Cookie
   - `WECHAT_WEBHOOK`：企业微信群机器人 Webhook（可选，推荐）
   - `ENABLE_PROXY`：访问论坛超时/失败时设 `true`
   - `PROXY_SOURCES`：一般留空即可
   - 自建应用回退：`WECHAT_CORPID` / `WECHAT_CORPSECRET` / `WECHAT_AGENTID` / `WECHAT_TOUSER`
2. 推送代码后，Actions 按 `signin.yml` 的 `cron: '0 1 * * *'`（UTC 01:00 = 北京时间 09:00）每天自动运行。
3. 手动验证：Actions 页面 → 对应 workflow → **Run workflow** 触发一次。

> GitHub 计划任务在高峰期可能延迟几十分钟，属正常。

## 本机本地运行

```bash
pip install -r requirements.txt

# 方式 A：export 环境变量
export MT_COOKIES="bbs_auth=...; bbs_saltkey=..."
export WECHAT_WEBHOOK="https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=..."
python main.py

# 方式 B：写入 .env（已加入 .gitignore，不会误提交）
#   MT_COOKIES=...
#   WECHAT_WEBHOOK=https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=...
python main.py
```

## 部署到青龙面板（QL）

1. **依赖**：青龙 → **依赖管理** → 新建依赖，类型 `pip`，填入 `requests`、`beautifulsoup4`。
2. **环境变量**：青龙 → **环境变量** → 新建，按需添加 `MT_COOKIES` / `MT_ACCOUNTS` / `WECHAT_WEBHOOK` / `ENABLE_PROXY`。
3. **新建任务**：青龙 → **定时任务** → 新建任务：
   - 命令：`python /ql/data/scripts/MT签到/main.py`（路径按实际存放位置填）
   - 定时规则：`0 9 * * *`（北京时间 09:00）
4. 点「运行」手动验证一次，看日志与群推送。

## 排错

| 现象 | 处理 |
|------|------|
| `未检测到登录态(Cookie无效/过期)` | 重新导出 Cookie |
| `签到页命中JS挑战` | 设 `ENABLE_PROXY=true` 或换网络 |
| 运行变红 `connect timeout` | 开 `ENABLE_PROXY`，或改在本机/自托管 runner 运行 |
| 自建应用推送 `errcode 60020` | 改用 `WECHAT_WEBHOOK` 群机器人 |
| 密码登录失败 | 改用 `MT_COOKIES`（Cookie 复用） |
| `未能获取签到formhash` | 检查网络 / 代理 |

## 许可证

本项目以 [LICENSE](./LICENSE)（GPLv3）发布。
