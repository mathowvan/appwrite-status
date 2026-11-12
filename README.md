# Appwrite Functions 状态页

面向 Appwrite Cloud Python Functions 的只读状态页，使用 Python 标准库，无第三方依赖。仅维护本仓库代码与说明。主页提供公开源码链接：[mathowvan/appwrite-status](https://github.com/mathowvan/appwrite-status)。

## 路由与边界

- `GET /`：中文深色响应式 HTML，固定六卡、公开源码链接。
- `GET /api/status`：JSON 状态快照。
- `GET /healthz`：`ok` 文本。
- 其他路径 404；非 GET 405。

匿名只读；不检查请求头、请求体或用户环境变量，不读取主机名、IP、网络状态、Appwrite 用户数据、API key 或凭据；不发起外网请求（页面中的源码链接由用户主动点击）。不新增函数/API、区域调整、付费服务或依赖。页面无脚本、外部资源、自动轮询、保活或定时任务。仅通过固定 PATH 查找 curl、wget、git，并各自运行固定版本参数；`shell=False`，执行有超时，除此之外不启动采集子进程。

## 指标范围与降级

所有内容是本次函数执行实例可见的有限读数，不代表主机、套餐、账户配额或独占资源。cgroup 详细项先只读取 `/proc/self/cgroup`，只有 v2 `0::/` 或 v1 对应 memory、cpu/cpuacct 成员路径为 `/` 时，才读取固定根挂载文件；不拼接成员私有路径、不回显成员路径或容器标识。无法验证时省略详细值或返回 null。v1 与 v2 内存统计不混源；限额为 0、`2**60` 及以上哨兵、无限、缺失或无效时不当作有限限额；用量大于限额时不计算百分比或剩余量。Swap 仅报告 v2 的有限 `memory.swap.current` 与 `memory.swap.max` 配对，v1 swap 完全不采集；`max`/不限额不推测。

cgroup CPU 限额与累计统计按验证后的固定层级读取。v2 `cpu.stat` 的微秒时间统一转为秒输出；v1 cpuacct 的纳秒用量转为秒，v1 cpu.stat 周期计数按原计数输出。CPU 统计是累计读数而非实时速率。当前 Python 进程指标来自 `resource.getrusage(RUSAGE_SELF)` 的用户/内核 CPU 秒、Linux maxRSS（转换为字节）及 `/proc/self/status` 白名单中的 VmRSS、VmHWM、VmSize、Threads；VmSize 是虚拟地址空间，不是物理内存。

根挂载磁盘容量用二进制单位展示，并保留 JSON 的 `total_bytes`、`used_bytes`、`free_bytes`、`available_bytes` 与格式化字段及使用率；容量与 inode 分开采集、分别失败降级。inode 可用数使用 `f_favail`，不会将 `f_ffree` 冒充可用数。挂载可能共享，非函数配额。系统与运行时字段包括 Python/实现/指针位数（由指针大小计算）、字节序、OS/架构、OpenSSL；模块载入时长不是 uptime。缺失的新增 HTML 指标不显示；原有关键读数可以表达不可用。JSON 保留既有顶层及资源字段，并扩展 `memory`、`swap`、`cgroup_cpu_stat`、`process`、磁盘字段和运行时字段；消费者应忽略未知字段并允许新增字段为 null。

缓存仅限当前暖 Python 进程，30 秒内返回同一快照。请求触发采集，无后台轮询。范围、挂载隔离和指标可读性不能证明平台租户隔离或实际配额。

## 本地检查

```sh
python3 -W error::ResourceWarning -m unittest discover -s tests -v
python3 -m compileall -q src tests
```

