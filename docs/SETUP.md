# 环境准备

这份文档记录本项目的开发与提交流程。按顺序做一遍即可，大约五分钟。

## 1. 安装 Git

`moon update` 会用 git 克隆 mooncakes 的 registry 索引，因此**没有 Git 就无法安装
任何第三方依赖**（本项目容器层目前零依赖，缺 Git 也能编译与测试）。推送代码
到 GitHub 同样需要 Git。

- Windows：`winget install --id Git.Git -e`，或从 <https://git-scm.com/download/win> 下载安装。
- macOS：`brew install git`。
- Linux：`sudo apt install git` 或对应发行版的包管理器。

装完后**重新打开终端**，用 `git --version` 确认。

## 2. 配置提交身份

在本仓库目录下执行（仓库级配置，不影响其他项目）：

```bash
git config user.name "kobe108"
git config user.email "3360944005@qq.com"
```

如果想让整台机器的项目都用这个身份，把命令改成加 `--global`。

## 3. 初始化并提交

```bash
git init -b main
git add .
git status          # 确认 _build/ 与 target/ 没有被加入（.gitignore 已覆盖）
git commit -m "feat: KDBX 4.x outer header and variant dictionary"
```

提交信息建议采用约定式提交（`feat:` / `fix:` / `docs:` / `test:`），
这样后续要生成变更日志时不用回头整理。

## 4. 推送到 GitHub

先在 GitHub 上创建一个空仓库 `kobe108/kdbx.mbt`（不要勾选自动生成 README，
否则第一次推送需要先拉取合并），然后：

```bash
git remote add origin https://github.com/kobe108/kdbx.mbt.git
git push -u origin main
```

## 5. 刷新依赖与验证

```bash
moon update                 # 需要 Git
moon check && moon test     # 类型检查与测试
moon fmt --check            # 格式检查（CI 也会跑）
moon run cmd/kdbx           # 运行命令行工具
```

## 6. 关于身份

本项目的仓库、模块名与提交身份是**同一个身份**，不要与其他账号混用：

- **GitHub 仓库**：`kobe108/kdbx.mbt`
- **MoonBit 模块名**：`kobe108/kdbx`（与仓库同名同归属）
- **提交身份**：`kobe108 <3360944005@qq.com>`

两点注意事项：

1. 第 2 步的 `git config` 一律不加 `--global`。全局身份会泄漏到其他仓库，
   也会让本项目的提交带上别的账号痕迹。
2. 不要把本模块发布到其他账号的 mooncakes 命名空间下。模块名 `kobe108/kdbx`
   只有在 mooncakes 上存在同名账号时才能发布；如果本机 MoonBit 凭据属于另一个
   账号，`moon publish` 会被拒绝——这正是我们想要的结果，不要去绕过它。

## 7. 依赖与许可证

引入任何第三方包时，需要同时更新 README 的依赖表与 `docs/DESIGN.md` 的依赖策略，
至少包含：包名、版本、许可证、用途，以及是否用公开测试向量交叉验证过。
