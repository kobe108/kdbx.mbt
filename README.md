# kdbx.mbt

用 MoonBit 打开、检查并体检 KeePass 密码库（KDBX 4.x）。

> KeePass 的 `.kdbx` 文件是很多人和团队最敏感的一份数据，但到目前为止，
> MoonBit 生态里没有任何实现能读它。这个项目从公开的
> [KDBX 4.1 规范](https://keepass.info/help/kb/kdbx.html)出发，用纯 MoonBit
> 把它做成可运行、可测试、可用于自动化流程的工具链。

## 为什么是这个问题

- **真实需求**：密码库需要被审计（弱口令、重复使用、过期、长期未更换），
  也需要被脚本化的流程读取（迁移、报表、合规检查），但把 `.kdbx` 交给脚本之前，
  总得有人先实现它。
- **生态空白**：2026-10-13 在 mooncakes.io 上检索 `kdbx`、`keepass`、
  `keepassxc`、`password-manager`、`kdbx4` 等关键词均为 0 条结果；
  生态里有大量密码学原语，却没有把格式规范落地成产品的这一层。
- **可验收**：KDBX 是公开规范（签名、头部字段、密钥派生、HMAC 块流都可逐字节核对），
  并且有成熟实现可以互操作测试，正好适合"边界清晰、一个月内可交付并验证"的项目。

## 当前进度

| 层次 | 内容 | 状态 |
| --- | --- | --- |
| 字节层 | 带边界检查的小端读写器 / 写入器 | 已完成 |
| 编码层 | 十六进制编解码（规范摘录、测试向量直接可用） | 已完成 |
| 容器层 | KDBX 4.x 外层头部解析与序列化、版本判定、end-of-header 校验 | 已完成 |
| 容器层 | VariantDictionary 编解码（KDF 参数、插件数据的载体） | 已完成 |
| 密码学 | SHA-256、SHA-512 与 HMAC-SHA-256（FIPS 180-4 / RFC 4231 官方向量验证） | 已完成 |
| 密码学 | AES-256 分组加密（FIPS-197 用例 + 独立实现交叉验证，加密方向） | 已完成 |
| 密钥层 | 复合主密钥、AES-KDF 与加密密钥/HMAC 密钥派生 | 已完成 |
| 密钥层 | Argon2d / Argon2id（KeePassXC 默认 KDF，必达） | 进行中 |
| 密钥层 | 头部 SHA-256 与 HMAC-SHA-256 校验（含篡改与截断检测） | 已完成 |
| 数据层 | HMAC 块流校验、AES-256-CBC 解密、PKCS#7 去填充 | 已完成 |
| 数据层 | inner header 结构化解析（随机流与附件） | 已完成 |
| 数据层 | gzip 解压（DEFLATE 三种块类型，CRC32 校验） | 已完成 |
| 数据层 | 外层 ChaCha20（按头部 UUID 分派） | 已完成 |
| 数据层 | 内层 ChaCha20 随机流（`Protected` 字段） | 已完成 |
| 数据层 | Salsa20 内层随机流（必达） | 计划中 |
| 模型层 | XML 解析与金库模型（分组树、条目、字段、保护标志） | 已完成 |
| 模型层 | `Protected` 字段与内层随机流解密（ChaCha20） | 已完成 |
| 产品层 | CLI：`info` / `ls` / `show` / `audit` / `export` | 计划中 |

完整的分层设计、规范出处与到 10 月 31 日的里程碑见
[docs/DESIGN.md](docs/DESIGN.md)。

按"一次一个功能"推进的功能清单与每项的验收标准见
[docs/ROADMAP.md](docs/ROADMAP.md)。

## 仓库与身份

- GitHub 仓库：`github.com/kobe108/kdbx.mbt`
- MoonBit 模块名：`kobe108/kdbx`，与仓库同属一个身份
- 提交身份：`kobe108 <3360944005@qq.com>`，只在本仓库内设置，不使用全局配置
- 开发环境准备见 [docs/SETUP.md](docs/SETUP.md)

## 快速开始

```bash
moon check          # 类型检查
moon test           # 运行测试
moon run cmd/kdbx   # 命令行工具（当前打印用法与进度）
```

### 环境要求

- **MoonBit 工具链**：官方安装脚本 `curl -fsSL https://cli.moonbitlang.com/install/unix.sh | bash`
  （Windows 见官方文档），建议 0.1.20260920 或更新版本。
- **Git**：`moon update` 会用 git 克隆 mooncakes 的 registry 索引，
  因此安装任何第三方依赖都需要本机有 Git。

## 代码示例

```moonbit
// 从一个 KDBX 4.1 文件的前若干字节出发解析外层头部。
let header = parse_outer_header(raw_bytes)
println(header.revision())          // "4.1"
println(header.cipher().to_text())  // "AES-256-CBC"
println(header.compression().to_text())
for entry in header.kdf_parameters().entries() {
  let (name, value) = entry
  println("\{name} = \{value.to_text()}")
}
```

## 设计原则

1. **先证明，再解析**：每个 `read_*` 都先检查剩余字节数，畸形文件返回类型化错误，
   不会因为越界而崩溃。
2. **规范即测试**：测试里直接写规范中的字节序列（例如
   `31C1F2E6BF714350BE5805216AFC5AFF` 是 AES-256-CBC 的标识），
   而不是"把实现跑一遍当作期望值"。
3. **依赖克制**：容器层只依赖 `moonbitlang/core`。密码学原语与 gzip 解压
   是否引入第三方包由 [docs/DESIGN.md](docs/DESIGN.md) 的依赖策略决定。
4. **真实文件才作数**：互操作测试使用真实的 KDBX 文件（按许可证要求，
   测试数据不随仓库分发，见设计文档）。

### 测试数据从哪来

仓库里的 fixtures（例如头部验签用的 271 字节 KDBX 4.1 文件前缀）**由
[scripts/make_fixture.py](scripts/make_fixture.py) 按规范生成**，不是从别处拷来的二进制，
来源可复现、许可证干净、不含任何真实凭据。需要与 KeePass / KeePassXC 产出物
互操作时，测试按固定提交号从上游下载，不随仓库分发。

## 许可证

Apache-2.0，见 [LICENSE](LICENSE)。

---

## English summary

`kdbx.mbt` is a MoonBit toolkit for KeePass KDBX 4.x databases: parse the outer
header, decode the variant dictionary, verify the header HMAC, decrypt and
inspect the encrypted payload, and audit a vault for weak, reused, stale or
expired credentials from the command line. The container layer is written in
pure MoonBit and currently depends only on `moonbitlang/core`; every parsing
step is bounds-checked and covered by tests written against the published KDBX
specification. The goal is to make KeePass databases usable from MoonBit
programs without leaving the ecosystem.
