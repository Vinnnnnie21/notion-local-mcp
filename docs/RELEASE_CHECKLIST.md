# 开源发布检查清单

这份清单对应本地候选仓库。勾选项必须有命令输出、测试日志或人工审阅记录；单元测试通过不能替代干净主机验收。

## 已完成

- [x] 文档包已在独立临时目录检查并解压：7 个条目、约 28 KB，无绝对路径、`..` 路径或符号链接。
- [x] 生产服务只读核对：用户级 `linux-code-mcp-v2.service` 仍运行于生产目录；本候选未修改其配置、状态、认证或服务。
- [x] 从当前运行入口导出 `app/` 源码、完整本地 imports、测试和依赖声明；未复制生产 state、backup、token、数据库或离线缓存。
- [x] 运行时硬编码路径改为环境变量，服务名改为配置项；默认服务名为 `notion-local-mcp.service`。
- [x] 生成真实 schema 对应的 `config.example.json` 和不会覆盖现有文件的 `scripts/init.py`。
- [x] 提供 `scripts/check_environment.py`、`scripts/install.py`、用户级 systemd 模板和可移植单元测试 CI。
- [x] MIT 全文采用 `Copyright (c) 2026 Vinnnnnie21`；README、SECURITY 和 CONTRIBUTING 明确第三方依赖继续使用各自许可。
- [x] 项目拥有者和发布账号确认为 `Vinnnnnie21`，公开仓库为 `Vinnnnnie21/notion-local-mcp`。
- [x] 候选文件扫描未发现生产路径、个人邮箱、真实 IP、生产域名、token 或私有业务数据。

## 发布前阻塞项

- [ ] 完成逐文件来源与第三方权利核查；不确定的第三方代码必须补充来源和 notices，保留原作者声明。
- [ ] 生成并审阅带 SHA256 的依赖锁定文件，核对 MCP SDK、Python 包、Node、PostgreSQL、Chromium 和 cloudflared 的版本来源与许可证。
- [ ] 在不含生产凭据、配置、状态和项目的干净 Linux 主机按 README 从头安装。
- [ ] 在干净主机完成认证 `tools/list`、`tools/call`、演示项目读写、隔离执行、超时、取消、输出分页、请求去重、UNKNOWN、数据库、HTTP、浏览器和清理验收。
- [ ] 用现场输出填入版本、测试数量、跳过项和失败原因；不把私有部署测试数量当成通用保证。
- [ ] 实际测试 HTTPS 隧道或反向代理的认证头、流式响应、证书和公网边界，不开放内部 8001。
- [ ] 确认 GitHub Private vulnerability reporting 已开启，并在仓库设置中复核私密报告渠道。
- [ ] 首次发布前审阅 `git diff --cached`、Git 历史和待提交文件；秘密扫描只作为辅助。

## 交付限制

仓库已创建并推送 `main` 分支，但尚未发布 Release。当前仍未达到“干净环境和真实 Notion 验收全部完成”的最终发布门槛。
