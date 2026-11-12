# Appwrite Functions 状态页

面向 Appwrite Cloud Python Functions 的只读状态页，使用 Python 标准库，无第三方依赖。主页提供公开源码链接：[mathowvan/appwrite-status](https://github.com/mathowvan/appwrite-status)。

## 路由与边界

- `GET /`：中文深色响应式 HTML，固定六卡、公开源码链接。
- `GET /api/status`：JSON 状态快照。
- `GET /healthz`：`ok` 文本。
- 其他路径 404；非 GET 405。

匿名只读。网络信息严格限于当前本地网络命名空间的接口状态、地址、默认 IPv4 网关、MTU 与累计接口计数；不查询公网出口地址，不进行任何外部网络查询。网络采集只使用只读 ioctl 及 `/proc/net/{dev,route,if_inet6}`。不检查请求头、请求体或用户环境变量，不读取主机名、MAC、DNS 搜索域、Appwrite 用户数据、API key 或凭据。页面无脚本、外部资源、自动轮询、保活或定时任务。仅通过固定 PATH 查找 curl、wget、git，并各自运行固定版本参数；`shell=False`，执行有超时，除此之外不启动采集子进程。

## 指标范围与降级

所有内容是本次函数执行实例可见的有限读数，不代表主机、套餐、账户配额或独占资源。cgroup 详细项先只读取 `/proc/self/cgroup`，只有 v2 `0::/` 或 v1 对应 memory、cpu/cpuacct 成员路径为 `/` 时，才读取固定根挂载文件；不拼接成员私有路径、不回显成员路径或容器标识。无法验证时省略详细值或返回 null。v1 与 v2 内存统计不混源；限额为 0、`2**60` 及以上哨兵、无限、缺失或无效时不当作有限限额；用量大于限额时不计算百分比或剩余量。Swap 仅报告 v2 的有限 `memory.swap.current` 与 `memory.swap.max` 配对，v1 swap 完全不采集；`max`/不限额不推测。

cgroup CPU 限额与累计统计按验证后的固定层级读取。v2 `cpu.stat` 的微秒时间统一转为秒输出；v1 cpuacct 的纳秒用量转为秒，v1 cpu.stat 周期计数按原计数输出。CPU 统计是累计读数而非实时速率。当前 Python 进程指标来自 `resource.getrusage(RUSAGE_SELF)` 的用户/内核 CPU 秒、Linux maxRSS（转换为字节）及 `/proc/self/status` 白名单中的 VmRSS、VmHWM、VmSize、Threads；VmSize 是虚拟地址空间，不是物理内存。

根挂载磁盘容量用二进制单位展示，并保留 JSON 的 `total_bytes`、`used_bytes`、`free_bytes`、`available_bytes` 与格式化字段及使用率；容量与 inode 分开采集、分别失败降级。inode 可用数使用 `f_favail`，不会将 `f_ffree` 冒充可用数。挂载可能共享，非函数配额。系统与运行时字段包括 Python/实现/指针位数（由指针大小计算）、字节序、OS/架构、OpenSSL；模块载入时长不是 uptime。缺失的新增 HTML 指标不显示；原有关键读数可以表达不可用。JSON 保留既有顶层及资源字段，并扩展 `memory`、`swap`、`cgroup_cpu_stat`、`process`、磁盘字段和运行时字段；消费者应忽略未知字段并允许新增字段为 null。

状态快照仅在当前暖 Python 进程内缓存 30 秒；请求触发采集，无后台轮询。范围、挂载隔离和指标可读性不能证明平台租户隔离或实际配额。

## 网络与 IP

仍保留六卡：内存与进程、根挂载磁盘、CPU、运行时与工具、网络与 IP、模块与快照。系统与工具合并展示，没有删除原有指标。

本地接口最多 16 个，来源仅为当前网络命名空间：`socket.if_nameindex()` 枚举接口，Linux 只读 ioctl 获取已分配的 IPv4/前缀、MTU 与 UP/RUNNING 标记，`/proc/net/if_inet6` 获取 IPv6（每接口最多 8 个，去重）。UP/RUNNING 是内核接口标记，不是互联网连通性保证。`/proc/net/dev` 读取接口累计收发字节、报文、错包和丢包；`/proc/net/route` 只提取同时具有 UP/GATEWAY 标记、默认掩码为零的 IPv4 默认网关。固定文件读取有长度上限，接口名受验证；不建立 TCP 连接、不探测路由、不扫描端口，不读取完整连接表。JSON 的 network 对象仅含本地字段，并以 `local_only` 范围和 `external_queries: false` 明确没有进行外部查询。

这些地址只是当前网络命名空间可见的本地地址，可能是临时地址或共享地址，不代表公网出口地址、主机地址或入站可达性。接口计数可能包含运行时共享流量，是累计值而非速率、个人用户流量或项目月带宽。缺失本地字段按可用性降级省略；健康检查、404 和 405 路由不采集指标。

## 本地检查

```sh
python3 -W error::ResourceWarning -m unittest discover -s tests -v
python3 -m compileall -q src tests
```
