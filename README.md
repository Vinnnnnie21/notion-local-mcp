# notion 本机连接 mcp

这是一个自托管的 Linux MCP 服务，让 Notion AI 在明确授权的项目目录中读取文件，并在隔离开发副本里修改、测试和保存制品。

项目拥有者和发布账号：`Vinnnnnie21`。公开仓库地址：[Vinnnnnie21/notion-local-mcp](https://github.com/Vinnnnnie21/notion-local-mcp)。这是第三方工具服务，不是 Notion 官方工作区 MCP，也不代表 Notion 背书。

## 当前状态

这是已创建的公开仓库，包含运行源码、测试、配置模板、安装辅助脚本和用户级 systemd 模板。当前版本来自 `2.2.1-execution-reliability`。目前没有发布 Release。

尚未宣称所有 Linux 都支持：隔离执行需要用户级 systemd、cgroup v2、bubblewrap、namespaces，以及按需准备的 Node、Python、PostgreSQL 和 Chromium 运行时。没有这些条件时，服务必须明确失败，不会退回宿主 Shell。维护者还没有在不含生产资源的全新主机上完成本文档全部的浏览器、数据库和远程 Notion 验收，因此发布前仍需完成检查清单。

## 原理和边界

```text
Notion AI -> HTTPS 入口 -> 认证 MCP -> 授权项目 / 隔离开发副本
```

文件工具只访问配置中的授权根目录。开发命令进入独立的 mount、user、pid、network namespace 和用户 cgroup；隔离启动失败会报错。默认不开放外网，不挂载 SSH、云凭据、Docker socket 或日常浏览器资料。写回原项目需要哈希检查和明确的同步调用。多文件操作不是整体事务。

工具返回的文件、日志和制品会传给 Notion 及其处理服务。运行在本机不等于数据只留在本机。只登记你有权传输的演示项目或工作目录，认证值不要放入聊天、命令参数、截图、Git 或公开 issue。

## 支持矩阵

| 功能 | 支持情况 | 边界 |
| --- | --- | --- |
| 文件读取、搜索、哈希编辑 | 支持 | 仅授权根目录；敏感路径和链接有保护 |
| 隔离 Python、Node、测试和构建 | 支持条件 | 需要真实 namespace、cgroup 和只读运行时 |
| 临时 HTTP、SQLite、PostgreSQL、Chromium | 支持条件 | 只允许隔离副本登记的 loopback 服务 |
| 输出分页和制品 | 支持 | 受采集、持久化、响应和排空上限约束 |
| Git | 支持 | 默认只操作副本；默认不推送远端 |
| 固定 MCP 维护 | 支持条件 | 仅本机登记候选，不能自行扩权 |
| Windows/macOS 原生运行 | 暂不支持 | Linux VM/WSL 仍需逐项核验 |

## 安装

支持 Debian 13、Ubuntu 24.04 等具备用户级 systemd 和 cgroup v2 的 Linux 主机。先安装系统依赖：`python3`、`python3-venv`、`git`、`bubblewrap`、`util-linux` 的 `nsenter`，并在需要时安装 Node/npm、PostgreSQL 和 Chromium。用环境预检查看当前主机，不会修改系统：

```bash
python3 scripts/check_environment.py
python3 scripts/check_environment.py --strict
```

应用依赖安装在仓库虚拟环境中：

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r app/requirements.txt
```

发布前应生成并审阅带 SHA256 的依赖锁定文件；当前候选未随附锁定文件，也不随仓库发布 wheel 缓存或第三方二进制。各运行时和依赖包继续使用自己的许可证。

## 初始化私有配置

选择一个专门的演示项目目录。脚本只创建新文件，存在配置或认证时拒绝覆盖：

```bash
python3 scripts/init.py --project "$HOME/notion-mcp-demo"
```

它会在仓库外创建 `~/.config/notion-local-mcp/config.json` 和权限为 `0600` 的 token。默认只登记 `demo` 项目，写入范围限于 `src/*`、`tests/*`、`docs/*`、Python、Markdown 和文本文件；不要把 `/`、整个主目录、生产项目或含业务凭据的目录填入配置。编辑配置后先验证：

```bash
python app/manage.py --config "$HOME/.config/notion-local-mcp/config.json" validate-config
```

执行隔离需要只读运行时目录。把经过来源、版本和 SHA256 核验的 Python/Node 运行时、Node 模块、离线 Python wheel 缓存和可选 PostgreSQL runtime 放在环境变量所指位置：

```bash
export NOTION_MCP_NODE_RUNTIME=/opt/notion-local-mcp/node
export NOTION_MCP_NODE_NPM=/opt/notion-local-mcp/node-v20
export NOTION_MCP_PYTHON_RUNTIME=/opt/notion-local-mcp/python
export NOTION_MCP_PYTHON_CACHE=/opt/notion-local-mcp/dependency-cache/python
export NOTION_MCP_POSTGRES_RUNTIME=/opt/notion-local-mcp/postgresql
```

这些目录不是本项目的 MIT 内容，也不由安装脚本自动下载。

## 启动和检查

直接启动只监听 loopback：

```bash
python app/server.py \
  --config "$HOME/.config/notion-local-mcp/config.json" \
  --token-file "$HOME/.config/notion-local-mcp/token" \
  --port 8001
```

也可以把仓库安装到 `~/.local/share/notion-local-mcp`，复制 `systemd/notion-local-mcp.service` 到 `~/.config/systemd/user/`，然后执行：

```bash
systemctl --user daemon-reload
systemctl --user enable --now notion-local-mcp.service
systemctl --user status notion-local-mcp.service
```

先检查未认证请求必须失败，再使用不打印 token 的 smoke check：

```bash
curl --fail-with-body --max-time 5 http://127.0.0.1:8001/health
python app/smoke_check.py --port 8001 --token-file "$HOME/.config/notion-local-mcp/token"
```

`/health` 和 `/mcp` 都要求认证；未认证请求应得到 `401`。服务不会自动启动隧道。

## HTTPS 入口和 Notion 连接

试用时可以按 Cloudflare 官方文档安装并核验 `cloudflared`，再运行：

```bash
cloudflared tunnel --url http://127.0.0.1:8001
```

把输出的 HTTPS 地址追加 `/mcp`。临时地址会变化，不能写入配置或日志。长期运行可使用自己控制的命名隧道，或在公网 Linux 主机用自有域名和 HTTPS 反向代理转发到 loopback；公网只开放 HTTPS，不开放 8001，并确认代理传递认证头和流式响应且不记录认证头。

在 Notion 的自定义 MCP 连接中填写 `https://你的入口/mcp`，认证使用 `Authorization: Bearer <本机生成的 token>`。界面名称和管理员策略随 Notion 账号变化。连接后调用 `health`、`list_projects`、`get_capabilities`，以实际工具 schema 为准，不把工具数量当作验收结论。

## 第一个开发任务

先调用 `list_projects`，不要猜项目编号。创建副本后按顺序调用 `dev_environment_ready`、`dev_read`/`dev_list`、`dev_run`、`dev_task_status`、`dev_output`，最后按需 `dev_sync`、`dev_execution_cleanup` 和 `dev_workspace_close`。写入和同步都使用上一次完整哈希；新增文件使用 `expectedHash=missing`。

`requestId` 用于请求去重；同一个编号配不同参数会被拒绝。副作用结果未知时返回 `UNKNOWN`，不能自动重放，先查询原请求。`purpose=expected-test` 表示预期失败，`purpose=repair` 必须配稳定的 `repairId`，修复预算按项目和 profile 累计，创建新副本不会清零。超时可以设置 1 秒到 profile 上限，默认 60 秒。大输出用 `dev_output` 的字符游标分页，同时检查 `truncated`、`droppedBytes`、`outputComplete` 和排空限制。

## 测试和发布前检查

可移植单元测试不需要生产配置：

```bash
python3 scripts/test.py
```

完整隔离测试另需 bubblewrap、用户 systemd、cgroup v2、只读运行时缓存和浏览器/数据库。当前 CI 只运行可移植单元测试；Linux 全功能作业故意关闭，避免把 GitHub hosted runner 的能力误当作保证。发布前必须在干净、无生产凭据的 Linux 主机完成 `docs/RELEASE_CHECKLIST.md`，并把跳过项和原因记录下来。

## 常见故障

- `401`：检查 Notion 的认证字段和 token 文件权限，不打印 token。
- `429`：遵循 `Retry-After`；不要用新 `requestId` 重放写入。
- `隔离运行时不可用`：检查 `check_environment.py --strict`、运行时环境变量、bwrap、用户 systemd 和 cgroup；服务不会退回宿主执行。
- `UNKNOWN`：结果未知，先用原 `requestId` 查询，不重复执行副作用。
- 工具 schema 未更新：刷新 Notion 连接和会话，再检查服务日志摘要，不公开认证头。

## 安全和许可

漏洞报告方式见 [SECURITY.md](SECURITY.md)。仓库已启用 GitHub Private vulnerability reporting。MIT 许可证只适用于本项目原创代码和文档；Python、Node、PostgreSQL、Chromium、cloudflared、MCP SDK 及其他依赖继续遵循各自许可证。项目名称不构成 Notion 商标授权。

本项目不包含生产配置、token、私钥、日志、快照、状态库、离线 wheel、浏览器身份资料或个人项目代码。`.gitignore` 不能替代发布前的人工检查。
