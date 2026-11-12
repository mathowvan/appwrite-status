# Appwrite Functions 状态页

一个适配 **Appwrite Cloud Python Functions** 的只读状态页，使用 Python 标准库，无第三方依赖。项目源码不会启动 HTTP 服务器、不监听端口、不依赖 Docker，也不执行部署。主页醒目链接：[mathowvan/appwrite-status](https://github.com/mathowvan/appwrite-status)。

## 路由

- `GET /`：中文深色响应式 HTML 状态页，含手动刷新建议、固定工具版本和实例范围说明。
- `GET /api/status`：JSON 状态数据。
- `GET /healthz`：`ok` 文本。
- 其他路径：404；所有非 GET 方法：405，并返回 `Allow: GET`。

页面无外部脚本、字体、图像、跟踪或自动轮询。没有输入可控制命令、URL、文件路径。代码不读取或回显请求头、请求体、环境变量、主机名、IP 或网络状态；尤其不触碰 `X-Appwrite-key`。

## 本地检查

```sh
python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests
```

`requirements.txt` 仅说明运行时没有第三方包依赖。此项目**不是**常驻 HTTP 服务或平台 uptime 监控；函数按需调用，每次状态页请求由 Appwrite Functions 运行时执行。进程存活时长只表示该执行实例进程自启动以来的时间，不应理解为函数/服务连续在线时长。CPU、内存和磁盘读数只反映执行环境可读的 cgroup 与当前挂载，可能不可用或受隔离实现影响；不表示账户配额或独占硬件。固定 `curl`、`wget`、`git` 版本探测并行执行，限定单探测超时并以总等待预算约 0.8 秒结束；暖进程缓存 30 秒，探测结果不因每次调用重复累加延迟。无需自动刷新、轮询或定时任务，避免消耗执行额度或人为保活。

## Appwrite Cloud 部署适配（候选设置，尚未部署）

参考官方开发文档：[Functions - Develop](https://appwrite.io/docs/products/functions/develop)。文档中的 Python 多文件示例使用 `from .utils import add`，入口为 `def main(context)`，响应使用 `context.res.text(...)`；官方响应示例明确支持 `text(body, status, headers)` 形态。此项目按该约定使用 `from .status import ...` 与 `context.req.path` / `context.req.method`。候选设置为：源码根目录保留仓库根目录，入口 `src/main.py`；Python 版本使用 Appwrite 控制台当前可选的 Python 3.x 运行时。入口路径相对于所选源码根目录，不能将根目录改为 `src/` 后仍保留入口的 `src/` 前缀。仅在未来获授权并由操作者确认后，才创建函数、配置域名/HTTP 触发及允许的调用权限。

候选本地构建前测试命令：`python3 -m unittest discover -s tests -v && python3 -m compileall -q src tests`。Appwrite Cloud 的控制台选项、运行时版本可用性、源码根目录映射及构建配置应在真实部署前依当前官方控制台再次核实；这里不提供臆造的 `appwrite.json`，也不硬编码项目 ID、region 或 API key。公开函数 URL/公开执行权限会让任何人都可能调用并消耗额度；部署和公开访问必须在用户确认前停止，不属于本项目的创建或测试步骤。

## 官方资料

- [Appwrite Functions develop](https://appwrite.io/docs/products/functions/develop)：Python 相对导入、`main(context)`、请求路径/方法与 `context.res.text`。
- [Appwrite brand assets](https://appwrite.io/assets)：品牌色参考中包含 Appwrite Pink `#FD366E`，本页面仅用作点缀色，无需嵌入官方 Logo。
