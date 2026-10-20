# 互操作测试笔记

这一页记录"用别的实现产出的文件验证自己"时踩到的差异。它们是格式本身的历史
层次，不是本项目的 bug，但读程序必须知道自己在处理哪一版。

## 已完成的互操作证据

1. **真实 KeePassXC 文件的头部验签**（`tests/data/Format400.kdbx`，口令取自
   KeePassXC 的 `TestKdbx4.cpp`）：该文件用 Argon2d + ChaCha20 + gzip。
   本项目的 Argon2d、复合主密钥、密钥派生与 ChaCha20 IV 处理能够复现它的头部
   HMAC，测试见 `interop_header_wbtest.mbt`。
2. **Argon2 与独立实现在真实参数下一致**：取该文件的参数（m = 1 MiB、t = 2、
   p = 2、Argon2d、版本 0x13）与盐，本项目算出的 tag 与 argon2-cffi 完全相同，
   测试见 `interop_argon2_wbtest.mbt`。
3. **端到端 4.1 流程**：由 `scripts/make_fixture.py` 生成的 4.1 fixture 覆盖
   头部验签、块流、CBC/ChaCha20、gzip、XML 与 `Protected` 字段
   （`payload_wbtest.mbt`、`open_database_wbtest.mbt`）。

## 已知的版本差异（来自真实文件）

| 特征 | KDBX 4.0 | KDBX 4.1（本项目目标） |
| --- | --- | --- |
| HMAC 块流布局 | 块数据在前，MAC 在块尾（pykeepass 的写法） | MAC 在前，随后是索引、长度、密文 |
| 头部字段长度 | 4 字节 | 4 字节 |
| 头部认证 | SHA-256 + HMAC-SHA-256 | 同左 |
| 是否支持 | **不支持**（KDBX 3.1/4.0 明确报错） | 支持 |

## 为什么还没有 4.1 的端到端真实库测试

- KeePassXC 2.7 的图形界面与 CLI 默认写 **KDBX 3.1**；其仓库自带的测���库也是 3.1。
- pykeepass 4.2 写 **KDBX 4.0**，块流布局与 4.1 不同。
- 因此需要一个由 KeePassXC 2.8+（默认 KDBX 4）或 KeePass 2.5x 导出的 4.1 库。

## 加入 4.1 样本的步骤

1. 用 KeePassXC 2.8+ 新建一个库（口令、条目随意，不要放真实凭据）；
2. 记录口令，把文件放到 `work/realkdbx/`；
3. 运行 `work/gen_interop.py` 的同类脚本，把文件以十六进制嵌入测试
   （仓库不接收真实凭据，测试数据仅用于本地与 CI）；
4. 测试断言：`open_database` 成功、条目数与标题/用户名/口令符合预期；
5. `moon test` 全绿后提交。
