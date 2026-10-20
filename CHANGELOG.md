# 更新记录

## 2.2.8-service-timeout-validation · 2026-10-20

本次从当前 MCP 源码同步到公开仓库，相较公开的 2.2.1 版本包含以下变化：

- 新增 `dev_execution_diagnose`、`dev_execution_preserve`、`dev_execution_request_recovery` 和 `dev_execution_apply_recovery`。恢复需要本机独立批准；关闭修改过的副本前必须完成保存。
- 工作区保存改为持久化的异步请求。同一请求查询进度，不重复复制；服务重启时未完成请求转为 `unknown`，失败保留原副本。
- 凭据检查与输出脱敏按源码语法识别数值代次、字符串和比较表达式，诊断提供规则编号与相对文件位置。部分失败在审计中单独记录。
- 运行环境检查报告 Node/npm 版本、离线 npm 缓存和前端模块解析情况，新增现代 Node 工具链选择。
- 启动服务前校验 profile 的超时上限，无效请求不会占用服务或端口登记。

公开版本使用环境变量指定运行时目录，使用通用服务名和演示测试数据。源码导出不包含生产配置、认证、状态、备份或依赖缓存。新增测试及临时 HTTP 验证已通过，完整隔离环境与真实 Notion 验收仍待完成，详见 [验证记录](docs/VALIDATION.md)。
