# HTTP URL rewrite

HTTP 处理使用独立附加配置，与 Mihomo YAML 分开。当前支持明文 HTTP/1 的 URL 改写、302/307 与拒绝；上游 URL 可以使用 HTTPS，并保持正常的证书链与主机名验证。现有 TLS／QUIC 透明转发保持原路径。

```yaml
http-ports: [80, 8080]
rewrite:
  - pattern: '^http://old\.example/(.*)$'
    action: replace
    replacement: 'https://new.example/$1'
  - pattern: '^http://redirect\.example/'
    action: redirect307
    replacement: 'https://new.example/'
  - pattern: '^http://blocked\.example/'
    action: reject
```

规则按顺序仅执行首个匹配。`replace` 透明修改最终目标／path／query；`redirect302`、`redirect307` 返回本地重定向；`reject` 返回 403。`replacement` 对前三种动作必填，拒绝不能携带它；支持 `$1`、`${name}` 等 capture 与 `$$` 字面美元符号。最终 URL 必须为无 userinfo、fragment、控制字符的 HTTP/HTTPS URL。未知字段与动作失败。

`http-ports` 默认 `[80,8080]`，只控制 TUN／CONNECT 隧道内明文 HTTP 的候选端口；显式 HTTP 代理请求本身已经确定协议。未启用或非候选端口不预读、不创建处理任务。非 HTTP 前缀与代理 CONNECT 控制流按原字节回放后透明转发。候选端口按最长 10 秒首部期限分类；已确认的 HTTP 使用既有严格消息定界。HTTP/1 持久请求、chunked、Content-Length、临时响应、Upgrade、预读与半关闭复用同一套 HTTP 入站 framing／relay；正文流式透传。OPTIONS `*` 保留原语义，不执行 URL 动作。

最终 URL 确定后才通过同一资源代际的 Dispatcher 选路、建链。重定向／拒绝不预建上游，未读请求正文通过关闭当前连接隔离。同 origin 的 path/query 动作保留 TUN 已解析的实际目的 IP；HTTP Host／authority 仍使用逻辑 URL。跨 scheme／host／有效端口时重建 Host、清除旧目的的 sniff 提示，并剥离旧站点 Authorization/Cookie；已验证入口用户名和原来源／目的快照保留。内部 DoH、provider、GeoData、协议握手与 Controller 不进入业务处理。

## 输入与应用

- Invoke `validateConfig`、`start` 可以在 `configYaml` 之外传可选 `httpConfigYaml`；省略或空串表示关闭。
- Invoke `updateConfig` 同时接收主配置与可选 `httpConfigYaml`；省略保留当前附加配置，空串明确关闭。主配置与附加规则作为同一候选发布；坏候选保留旧代。
- CLI 使用 `-http-config <file>`／`--http-config=<file>`，只将显式路径传给 `foreground.httpConfigPath`，文件读取和验证归 foreground。没有环境或目录探测；不从 stdin 读取附加文件。显式空路径失败，空文件关闭处理。`-t` 同时验证两个配置且不初始化 dataDir。
- 普通 Controller PUT 主 YAML 和 provider 重建继承活动附加策略，不把规则塞回主 YAML。已建立 HTTP 连接固定其资源／规则代际；新连接取得新候选。
- Windows `startVpn` 的可选 `httpConfigYaml` 经过 Session Snapshot 的 canonical digest 和包内传递，在实际 Session Host 中构造相同策略；缺省快照保持原形式。启动 snapshotToken 的含义不因在线更新而改变。

必须编译 `inbound-http` 才能启用处理；缺少时非空附加输入明确失败。附加文档最多 1 MiB，最多 64 个规则和 64 个非零端口；单 pattern 2 KiB，replacement 与最终 URL 各 8 KiB，总规则文本 64 KiB。YAML 展开、正则编译和 capture 输出均在分配前保留局部预算。规则／信任与既有数据面按资源代共享；不新增全局业务配额、第二个 Dialer 或后台扫描任务。Stop 覆盖解析、上游握手、正文和透明 relay。
