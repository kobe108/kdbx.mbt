# 互操作测试

这里的每一条都是"用别的实现产出的文件验证自己"。它们抓出过两个真实的格式差异，
所以不只是走过场。

## 已完成

| 证据 | 内容 | 测试 |
| --- | --- | --- |
| 真实 KeePassXC 库端到端 | KeePassXC 2.7 新建的库（KDBX 4.0、AES-256-CBC、Argon2d、gzip），正确口令下验签、解密、解压、解析、解密 `Protected` 字段，并核对两条条目 | `interop_kdbx4_wbtest.mbt` |
| pykeepass：Argon2id + AES | 独立实现生成的真实 KDBX 4.0 库，头部验签、Argon2id、CBC、gzip、XML 与条目读取全部通过 | `argon2_wbtest.mbt` + 一键演示 |
| pykeepass：Argon2d + ChaCha20 | 独立实现生成的真实 KDBX 4.0 库，Argon2d 分派、外层 ChaCha20 与受保护字段读取全部通过 | 一键演示 |
| 真实库上的 CLI | 同一测试库通过 `info`、`ls`、`show` 运行；`show` 默认输出脱敏值，`--reveal` 才显示明文 | 本地实机验证 |
| 真实 KeePassXC 文件头部验签 | `tests/data/Format400.kdbx`（口令取自其 `TestKdbx4.cpp`）：Argon2d + ChaCha20 + gzip | `interop_header_wbtest.mbt` |
| Argon2 独立实现对齐 | 用真实库的参数（1 MiB、2 轮、2 lane、Argon2d）与盐，结果与 argon2-cffi 逐字节一致 | `interop_argon2_wbtest.mbt` |
| 4.1 全流程 | 自生成 fixture 覆盖 4.1 块流、CBC/ChaCha20、gzip、XML 与 `Protected` | `payload_wbtest.mbt` 等 |

## 互操作抓出的三个实现问题

1. **块流布局**：KDBX 4.0 的块是"标签 + 长度 + 数据"（索引隐含），
   4.1 是"标签 + 索引 + 长度 + 数据"。读取器按头部次版本号选择布局。
2. **内层随机流**：密码学输入不是原始密钥字节——ChaCha20 用 `SHA-512(密钥)` 的
   前 32 字节作 key、随后 12 字节作 nonce；Salsa20 用 `SHA-256(密钥)` 与固定 nonce。
   直接使用原始密钥会解出"看似合理"的乱码，而不是报错。
3. **Argon2id 地址块初始化**：首轮首个 slice 从索引 2 开始时，必须先初始化地址块。
   RFC 的小向量没有实际进入地址块循环，因此真实 1 MiB 库才暴露该问题；修复后新增
   pykeepass 生成参数作为永久回归测试。

## 关于测试文件的 KDF 成本

真实库用 Argon2d 64 MiB × 81 轮（KeePassXC 按约 100 ms 解密时间校准）。
原始文件已在本机端到端验证通过；提交进仓库的样本把 KDF 成本降到 1 MiB / 1 轮，
**载荷（inner header、XML、受保护字段）保持不变**，以便测试套件在几秒内跑完。
