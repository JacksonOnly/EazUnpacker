# EazUnpacker

面向 **Eazfuscator.NET 托管程序集**的命令行解包与反混淆工具。恢复可分析的 IL，生成可读名称，并可选导出 C# 工程。

**简体中文** · [English](README.en.md) · **v1.2.1** · [更新日志](CHANGELOG.md)

[快速开始](#快速开始) · [功能特点](#主要功能) · [字符串编辑](#原位编辑加密字符串) · [参数](#参数与退出码) · [开发](#开发与构建)

> 按元数据与 IL 语义识别保护。支持范围以实际恢复报告为准，不承诺任意程序集“完全还原”。

## 主要功能

| 能力 | 说明 |
| --- | --- |
| 字符串与资源 | 恢复受支持的字符串、资源及内嵌程序集；不脱壳编辑 Eaz 加密字符串；提取并核对 Costura 托管依赖身份 |
| VM 还原 | 识别 VM 格式和调用点，恢复受支持的指令、签名及异常区域；失败时保留原方法 |
| 内联与代理 | 恢复一个宿主内的多个 VM 调用；支持受约束的 `ref` 写回；整理透明代理链，内联有界的纯整数叶表达式 |
| 控制流 | 折叠可证明的整数/枚举条件，整理 switch 分发、跳转链与单前驱常量，删除不可达指令和无用局部写入 |
| 可读命名 | 按类型角色、继承和入口点生成名称，精简参数名，保留名称映射与 Portable PDB |
| 密钥日志 | 通过原校验后输出密钥、Token、输入中的原命名空间/类名/方法签名；保留结构化记录 |
| 可选源码导出 | 使用 ILSpy 导出 C# 工程、字符串索引并尝试重构建 |
| 可选 CLR 检查 | 显式检查恢复后的宿主、内联适配器及访问桥；**默认关闭** |

## 快速开始

### 1. 解压完整发布包

解压 `EazUnpacker-v1.2.1-win.zip`，保留 `worker\modern` 等所有子目录。入口为 `Unpacker.exe`，不要只复制 EXE。

- **运行环境**：Windows、.NET Framework 4.8；处理现代 .NET 目标还需要相应的 .NET Desktop Runtime。现代后端以 .NET 8 为目标，可向已安装的更新主版本滚动。
- **目录权限**：解压到较短的可写目录，程序会在自身目录建立 `temp`。Framework 加载器或第三方工具仍可能受 Windows 长路径限制。
- **是否需要 SDK**：普通解包不需要；源码重构建需要 .NET SDK 和目标项目所需引用。开发构建见[开发与构建](#开发与构建)。

### 2. 运行命令

在解压后的目录打开 PowerShell：

```powershell
# 默认：恢复 IL 并输出程序，不执行 CLR 准备检查，不导出源码
.\Unpacker.exe unpack ".\input\input.dll" ".\output\input_unpacked.dll"

# 显式开启 CLR 检查
.\Unpacker.exe unpack ".\input\input.dll" ".\output\input_unpacked.dll" --validate-clr

# 导出并尝试重构建 C#；CLR 检查仍需单独开启
.\Unpacker.exe unpack ".\input\input.exe" ".\output\input_unpacked.exe" --export-source --validate-clr

# 静态元数据分析，标准输出为 JSON
.\Unpacker.exe analyzer ".\input\input.dll"
```

### 3. 查看输出与结果

控制台会显示输出文件、诊断目录和结束统计。先确认退出码，再查看对应运行目录的 `result.json`；没有执行的检查不代表检查通过。

输入与输出不能相同。只要生成了恢复程序集，即使后续阶段未完成也会尽量发布，并明确记录部分完成状态。Framework EXE 的生成 `.config` 应与 EXE 一起部署；DLL 仍受宿主配置和依赖影响。

## 原位编辑加密字符串

```powershell
.\Unpacker.exe strings export ".\input\input.exe" ".\local\input.strings.json"
.\Unpacker.exe strings apply ".\input\input.exe" ".\local\input.strings.json" ".\output\edited.exe"
# 或覆盖原件，同时生成 .bak 备份
.\Unpacker.exe strings apply ".\input\input.exe" ".\local\input.strings.json" --in-place
```

只编辑清单中的 `text`；可删去不需要修改的条目。清单与导出时的程序绑定，再次编辑已改文件时需重新导出。清单含解密文本，请仅在本地保存。

支持可静态识别的托管 PE 嵌入字符串表。不执行目标程序，不改 IL，也不移动记录；新文本编码或压缩后必须装入原密文槽位。回写会重新解密核对；有条目无法写入时，不生成部分结果。修改会使已有数字签名失效，工具不会重新签名。

## 参数与退出码

| 参数 | 默认 | 作用 |
| --- | --- | --- |
| `--export-source` | 关闭 | 额外导出 C# 工程、字符串索引，并尝试编译 |
| `--validate-clr` | 关闭 | 开启恢复 IL 的 CLR 准备检查；同时导出源码时也检查重构建方法 |

选项可放在输入/输出路径之前或之后；未知或重复选项报错。未请求的可选阶段不计为恢复失败，未检查不代表检查通过。

| 退出码 | 含义 |
| --- | --- |
| `0` | 请求的处理阶段完成 |
| `2` | 已有输出，但恢复或显式请求的附加阶段未全部完成 |
| `1` | 参数、输入或处理错误 |

### 常用环境变量

| 变量 | 用途 |
| --- | --- |
| `UNPACKER_DEPENDENCY_PATHS` | 额外依赖目录；Windows 下用 `;` 分隔绝对路径 |
| `UNPACKER_VM_VERBOSE=1` | 输出更多映射信息 |
| `UNPACKER_VM_DEBUG=1` | 输出逐方法/指令等调试细节 |
| `UNPACKER_VM_KEY_SEARCH_LIMIT` | 有界整数候选搜索次数，默认 `65536`；`0` 禁用，上限一千万 |
| `UNPACKER_VM_KEY_SEARCH_SECONDS` | 整个模块的整数兜底搜索时间预算，默认 `20` 秒；单个校验器最多 `5` 秒，`0` 禁用，上限 `120` 秒 |
| `UNPACKER_VM_INT32_KEYS` | 显式整数候选，逗号分隔；仍须通过原校验 |
| `UNPACKER_VM_STRING_KEYS` | 显式字符串候选，使用 JSON 字符串数组；仍须通过原校验 |
| `UNPACKER_VM_USE_KEY_CACHE=1` | 允许读取显式指定的历史候选缓存 |
| `UNPACKER_VM_KEY_CACHE_PATH` | 候选缓存文件路径；不默认读取或捆绑预设密钥表 |

## 临时目录与输出位置

临时文件统一位于 **程序目录下的 `temp`**。这里的程序目录是 `Unpacker.exe` 所在目录，不是启动命令时的当前目录。

```text
Unpacker.exe
worker/
  Unpacker.Worker.exe
  modern/
temp/
  work/<输出路径哈希>/
    latest.json
    run-<时间>-<唯一标识>/
      result.json
      progress.log
      ...
  analysis-<唯一标识>/       # 分析结束后删除
```

主程序和配套 worker 共用该位置，子进程的 `TEMP` / `TMP` 也指向此处。程序目录必须可写；不可写时会报错，不静默转存其他位置。诊断、源码导出和重构建产物保留在对应运行目录；处理进程全部退出后可自行清理 `temp`。

## 第三方依赖与许可

组合项目采用 [GPL-3.0](LICENSE)。第三方组件保留各自许可证；来源、固定源码基线和本地修改说明见 [NOTICE](NOTICE)。

### 内置源码

| 组件 | 用途 | 许可证 |
| --- | --- | --- |
| [EazFixer](src/ThirdParty/EazFixer) | 字符串、资源与内嵌程序集恢复 | [MIT](src/ThirdParty/EazFixer/LICENSE) |
| [EazyDevirt](src/ThirdParty/EazyDevirt) | VM 格式识别、解码与 IL 恢复 | [GPL-3.0](src/ThirdParty/EazyDevirt/LICENSE) |
| [Echo](src/ThirdParty/Echo) | CIL 分析与解释基础设施 | [LGPL-3.0](src/ThirdParty/Echo/LICENSE.md) |

### 主要 NuGet 引用

| 包 | 项目固定版本 | 用途 |
| --- | --- | --- |
| dnlib | 4.5.0 | 托管元数据、IL 与 PDB 改写 |
| AsmResolver.DotNet | 6.0.0-beta.4 | VM 后端的 PE/元数据与 CIL 生成 |
| Lib.Harmony | 2.4.2 | 独立解码后端中的运行时适配 |
| BouncyCastle.Cryptography | 2.5.1 | VM 加密流相关实现 |
| ICSharpCode.Decompiler | 11.1.0.9782 | ILSpy C# 反编译与工程导出 |
| Newtonsoft.Json | 13.0.3 | 报告和进度序列化 |
| System.Memory | 4.6.3（主项目） | Framework 兼容支持 |

Echo 另保留其固定上游引用，如 `System.Collections.Immutable`、`Nullable`。完整直接/传递引用及其许可证以项目文件、NuGet 元数据和包内许可为准；这不是“最新版本”列表。

## 开发与构建

从仓库根目录执行。需要支持 `.slnx` 的 .NET SDK 和 .NET Framework 4.8 开发引用。可使用 .NET 10 SDK 构建。

```powershell
dotnet build Unpacker.slnx -c Release
```

构建入口为 `src\bin\Release\net48\Unpacker.exe`。发布脚本从提交快照构建，并排除本地输入、缓存及临时文件：

```powershell
pwsh -File .\scripts\Build-Release.ps1
```
