# 设计方案

本文档记录 `kdbx.mbt` 的选题依据、范围边界、技术设计、测试策略与到
2026-10-31（十月赛报名与验收截止）的里程碑。它同时是提交材料的一部分：
赛事验收看重边界清晰、测试质量、开源合规与可维护性，所以这里逐条说明。

## 1. 选题

**做 KeePass KDBX 4.x 的 MoonBit 读写与密码库体检工具。**

一句话价值主张：让 MoonBit 程序与命令行脚本能安全地打开、检查和体检自己的
KeePass 密码库，而不必把文件交给其他语言的工具链。

三个真实用户场景：

1. **个人 / 团队安全体检**：读出所有条目，报告弱口令、重复使用、长期未更换、
   已过期的凭据，输出 JSON 或 Markdown 报告，方便贴进工单或周报。
2. **迁移与脚本化**：把条目导出为 CSV 或 JSON，用于迁移到其他密码管理器、
   生成资产清单或做合规检查。
3. **MoonBit 生态能力**：为 MoonBit 提供一套"从规范到产品"的示范，
   覆盖二进制格式解析、密钥派生、HMAC 校验、命令行工具与文档测试。

## 2. 差异化证据（为什么不会与已有项目重叠）

检索方法与时间：**2026-10-13**，通过 mooncakes.io 的公开检索接口
`https://mooncakes.io/api-new/v0/search?kw=<关键词>` 逐词检索，
共覆盖约 300 个关键词，横跨文件格式、协议、密码学、数据处理与开发工具等方向。

关键结果：

- `kdbx`、`kdbx4`、`keepass`、`keepassxc`、`bitwarden`：**0 条结果**（两轮复核一致）。
- `password-manager`、`password-audit`、`credential-store` 的命中都是无关项目的
  描述文本（例如通用密码学库提到 "password manager" 场景），
  **没有密码库格式实现，也没有密码库审计工具**。
- 生态中密码学原语非常丰富（AES、ChaCha20、Argon2、HMAC、HKDF、scrypt 等
  都能找到 Apache-2.0 的包），但**没有任何项目把 KDBX 规范落地**。
- 相邻但不同的方向已有不少项目（二进制序列化框架、通用解析器组合子、
  各种"审计与守门"工具），因此本项目边界必须落在
  **KDBX 容器 + 密码库语义**上，而不是做通用二进制解析或通用加密库。

结论：**在 KDBX 这个点上生态是空的；我们要做的是把这个点做深，而不是铺宽。**

## 3. 范围

### 3.1 MVP（必须在 10-31 前完成并演示）

- KDBX 4.x 外层头部解析与序列化（含版本判定、end-of-header 校验）。
- VariantDictionary 编解码（KDF 参数、插件数据）。
- 复合主密钥计算、AES-KDF、头部 HMAC-SHA-256 校验。
- AES-256-CBC 解密、HMAC 块流校验与拼接、inner header 解析、gzip 解压。
- XML 载荷解析为分组 / 条目模型（含 `Protected` 字段处理）。
- CLI：`info`、`ls`、`show`。
- 测试：规范向量、畸形输入、真实文件互操作。

### 3.2 进阶（有余力再做，按优先级排序）

1. `audit` 子命令：弱口令、重复使用、过期、长期未更换、缺少 TOTP 的报告，
   输出 Markdown 或 JSON，便于接入 CI。
2. `export` 子命令：CSV 或 JSON 导出，`--redact` 为默认，不输出明文口令。
3. KDBX 4.1 搭配 ChaCha20；KDBX 3.1 只读兼容。
4. Argon2d / Argon2id（KeePass 2.35+ 的默认 KDF，代价较高，见风险表）。
5. 写入路径：改写条目后重新加密保存（需要 XML 往返与头部哈希重算）。
6. 与 CI 集成：把 `audit` 结果作为退出码或 SARIF 报告用于门禁。

### 3.3 明确不做

- 不做密码学算法竞赛：优先复用生态中已有且经过测试的 MoonBit 包。
- 不做图形界面：定位是库加命令行工具，便于测试与脚本化。
- 不重复生态已有的东西：不写通用 JSON、XML 或压缩库，只做 KDBX 需要的最小子集。

## 4. 架构

分层从下到上：

- **基础层**：`byteio.mbt`（小端读写与边界检查）、`hex.mbt`、`error.mbt`。
- **容器层**：`header.mbt`（外层头部）、`variant_dict.mbt`（键值字典）、
  `key_schedule.mbt`（复合主密钥与 KDF）。
- **数据层**：`block_stream.mbt`（HMAC 块流）、`cipher.mbt`（AES / ChaCha20）、
  `xml_model.mbt`（分组与条目模型）。
- **产品层**：`audit.mbt`（体检规则）、`report.mbt`（报告渲染）、`export.mbt`（导出）。
- **入口**：`cmd/kdbx`（命令行工具），只做参数解析与打印，逻辑全部在库里，
  这样 CLI 行为可以被单元测试覆盖。

设计约定：

- 所有解析函数先证明、再读取，失败返回 `KdbxError` 的窄变体，不 panic。
- 内部数据结构可变，对外读取接口是纯函数，便于测试与并行使用。

## 5. 规范要点（实现依据）

来源：KeePass 官方公开规范 <https://keepass.info/help/kb/kdbx.html>（KDBX 4.1）。

### 5.1 文件布局

文件顺序为：外层头部、头部 SHA-256、头部 HMAC-SHA-256、
HMAC 保护的块流（其中是"压缩后的 inner header 加 XML 文档"）。

- Signature (1)：`0x9AA2D903`，小端存储。
- Signature (2)：`0xB54BFB67`；KeePass 1.x 使用 `0xB54BFB65`，本项目不支持。
- Format version：高 16 位主版本、低 16 位次版本，KDBX 4.1 为 `0x00040001`。
- 头部字段：`id(1 字节) + size(Int32 小端) + value`，以 id 0 结束。
- 头部 SHA-256：无需密钥即可发现头部损坏。
- 头部 HMAC-SHA-256：校验头部真实性与完整性，需要主密钥。

### 5.2 外层头部字段（KDBX 4.x）

| ID | 名称 | 类型与取值 |
| --- | --- | --- |
| 0 | End of header | `0x0D 0x0A 0x0D 0x0A` |
| 2 | Cipher ID | AES-256-CBC `31C1F2E6BF714350BE5805216AFC5AFF`；ChaCha20 `D6038A2B8B6F4CB5A524339A31DBB59A` |
| 3 | Compression | 0 表示不压缩，1 表示 GZip |
| 4 | Master seed | 32 字节 |
| 7 | Encryption IV | AES 为 16 字节，ChaCha20 为 12 字节 |
| 11 | KDF parameters | VariantDictionary |
| 12 | Public custom data | VariantDictionary |

ID 1、5、6、8、9、10 属于 KDBX 3.1；读取老文件时需要容忍这些字段的存在。

### 5.3 VariantDictionary

版本 `0x0100`（高字节为主版本，必须为 1），随后是若干条目，最后是 `0x00` 终止符。
条目为 `type(1) + name_len(Int32 小端) + name(UTF-8) + value_len(Int32 小端) + value`。
类型包括 `0x04` UInt32、`0x05` UInt64、`0x08` Bool、`0x0C` Int32、`0x0D` Int64、
`0x18` String、`0x42` Byte[]。条目顺序任意，本项目保持插入顺序以便逐字节往返。

### 5.4 密钥派生

- 复合主密钥 `R`：对各密钥分量按顺序拼接后取 SHA-256；分量包括
  主口令的 SHA-256、密钥文件中的密钥、密钥提供者插件提供的密钥等，均可选。
- 变换结果 `T`：用头部 KDF 参数对 `R` 做变换。
- 加密密钥：`SHA-256(S 加 T)`，其中 `S` 是头部中的 master seed。
- 头部 HMAC 密钥：`SHA-512(0xFFFFFFFFFFFFFFFF 加 SHA-512(S 加 T 加 0x01))`。
- 第 `i` 个数据块的 HMAC 密钥 `Ki`：`SHA-512(i 加 SHA-512(S 加 T 加 0x01))`。

KDF 标识：AES-KDF 为 `C9D9F39A628A4460BF740D08C18A4FEA`，
Argon2d 为 `EF636DDF8C29444B91F7A9A403E30A0C`，
Argon2id 为 `9E298B1956DB4773B23DFC3EC6F0A1E6`。

### 5.5 HMAC 块流

每块为 `HMAC-SHA-256(32 字节) + index(UInt64 小端) + size(UInt32 小端) + ciphertext`，
`size` 为 0 表示最后一块。HMAC 的输入是 `index + size + ciphertext`，
密钥按 5.4 的方式逐块派生。KeePass 写出时块大小通常为 1 MB。

## 6. 测试策略

| 类别 | 做法 | 目的 |
| --- | --- | --- |
| 规范向量 | 直接写规范里的字节序列（签名、UUID、字段布局、VariantDictionary 实例） | 证明实现符合规范，而不是"自己和自己一致" |
| 往返测试 | 解析、重新编码、逐字节比较 | 保护写路径与头部哈希校验 |
| 畸形输入 | 截断、签名错误、版本超前、非法 UTF-8 | 证明不会 panic，错误可分类 |
| 密钥派生 | 固定口令加固定种子，验证 `R`、`T`、加密密钥与 HMAC 密钥 | 密钥派生最容易静默出错 |
| 互操作 | 用真实的 `.kdbx` 文件验证读取结果 | 证明真的能打开别人创建的文件 |
| 属性测试 | 对头部字段与 VariantDictionary 做随机往返 | 覆盖手写用例想不到的组合 |

**测试数据与许可证**：真实 `.kdbx` 测试文件不随仓库分发（上游测试数据的许可证
与我们的 Apache-2.0 不一致）。集成测试在本地或 CI 中从上游仓库按固定提交号下载，
只使用公开的、专门用于测试的库文件。仓库内自带的 fixture 一律由我们自己生成，
且不含任何真实凭据——这一点对安全类项目尤其重要。

## 7. 依赖策略

- 起步阶段只依赖 `moonbitlang/core`，容器层、字节层、编码层全部自研。
- 需要密码学与压缩能力时，按以下顺序决策，并在 README 中登记（含许可证）：
  1. 生态中是否已有维护良好、许可证兼容（Apache-2.0 或 MIT）的 MoonBit 包；
  2. 若有，优先复用，并用公开测试向量交叉验证其输出；
  3. 若没有或质量不足，再自研最小实现。
- 已知候选：`cc06b/mooncry`（Apache-2.0，含 AES-CBC、ChaCha20、Argon2、HMAC、SHA-2），
  `moonbit-community/flate`（Apache-2.0，DEFLATE 与 gzip）。
  注意：安装第三方依赖需要本机安装 `git`，因为 `moon update` 依赖它。
- 所有依赖必须在 README 的依赖与许可表中列出名称、版本、许可证与用途。

## 8. 里程碑（2026-10-13 到 10-31）

| 阶段 | 日期 | 目标 | 交付物 |
| --- | --- | --- | --- |
| 0 | 10-13 | 容器骨架落地 | 头部解析、VariantDictionary、测试全绿（已完成） |
| 1 | 10-14 到 10-16 | 密钥层 | 复合主密钥、AES-KDF、头部 SHA-256 与 HMAC 校验，含向量测试（SHA-256 与 HMAC-SHA-256 已完成） |
| 2 | 10-17 到 10-19 | 解密路径 | AES-256-CBC、HMAC 块流、inner header、gzip 解压 |
| 3 | 10-20 到 10-23 | 数据模型与 CLI | XML 转分组与条目模型，`info`、`ls`、`show` |
| 4 | 10-24 到 10-27 | 互操作与审计 | 真实 `.kdbx` 互操作测试，`audit` 报告（Markdown 与 JSON） |
| 5 | 10-28 到 10-31 | 收尾与提交 | 文档、演示、边界用例、提交材料（README、测试、许可证） |

## 9. 风险与对策

| 风险 | 影响 | 对策 |
| --- | --- | --- |
| Argon2 实现成本高 | 打不开 KeePass 新版本默认创建的库 | 优先支持 AES-KDF；Argon2 先用生态包，必要时降级为明确报错并给出提示 |
| 第三方包质量不可控 | 静默算错密钥，最难排查 | 用公开测试向量交叉验证；密钥派生单独抽出并有独立测试 |
| gzip 与 XML 依赖 | 影响能打开的文件范围 | 只实现 KDBX 实际用到的子集；先跑通压缩选项为 none 的文件 |
| 测试数据许可证 | 可能违反开源合规 | 不分发上游测试文件；CI 按固定提交号下载 |
| 范围膨胀 | 18 天做不完 | MVP 只保读路径与 `info`、`ls`、`show`；写入与 ChaCha20 明确列为进阶 |
| 本机缺少 Git | 无法安装第三方依赖 | README 明确说明；容器层保持零依赖，缺 Git 也能编译与测试 |
| AES-KDF 性能 | 真实库常用数百万轮 AES 变换，纯 MoonBit 可能耗时过长 | 实测：release 下约 85 万轮/秒（600 万轮约 7 秒，6000 万轮约 70 秒），见 docs/ROADMAP.md；已做掉 ShiftRows 的每轮拷贝，进一步优化需 T 表 |
| 测试数据来源 | 借用别人的 `.kdbx` 测试文件会带来许可证问题 | fixtures 由仓库内 `scripts/make_fixture.py` 按规范生成，来源可复现；互操作测试再按固定提交号下载上游文件 |

## 10. 验收标准对照

| 赛事要求 | 本项目如何满足 |
| --- | --- |
| 以 MoonBit 为主要实现语言 | 全部逻辑为 MoonBit，CLI 也是 MoonBit 可执行程序 |
| 仓库公开、提交连续可追踪 | 常规 commit 与 PR 流程，CI 每次提交跑 check、test、fmt |
| 能够运行 | `moon test` 全绿，`moon run cmd/kdbx` 可直接演示 |
| 提供 README、示例与测试 | README 加本文档，分层测试覆盖规范向量、往返、畸形输入与互操作 |
| 开源合规 | Apache-2.0；依赖逐项登记许可证；测试数据不违规分发 |
| 可解释、AI 可用但责任在人 | 设计文档记录每个决策的规范依据，关键算法均有独立测试与出处 |
