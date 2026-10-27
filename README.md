# edit-fidelity

给 AI 编码助手用的**编辑保真**检查工具：防止改文件时字符被吞、内容被截断、定义被漏写、依赖被编造、代码语义写反，并在写完后用字节与结构证据核对。

不是提示词，是**可执行的检查器**。每个失败模式都有对应的判据和退出码。

```
python scripts/audit_all.py <file> [--before <snapshot>]
```

退出码 `0` 才算过。

---

## 为什么需要这个

模型改文件时的错误不是一种病，是 **21 种可分别检测的失败**。其中一部分能被脚本判，一部分不能——把这两类混在一起谈，就会得到"多加小心"这种没用的建议。

本项目把 21 种失败按**能不能用脚本判**分成三层，层 A/B 给了检查器，层 C 明确写"没有一行脚本能判"并给出让它变可判的手段。

---

## 三层失败模式

### 层 A · 字节层（脚本可判）

| 编号 | 问题 | 判据 | 脚本 |
|---|---|---|---|
| F1 | 转义被吞 / 加倍 | 反斜杠计数与 `--expect N` 比对 | `bs_audit.py` |
| F2 | 内容被截断 | 末尾悬空 `([{,:`=` 或反斜杠 | `edit_guard.py` |
| F8 | 编码 / 换行破坏 | 非 UTF-8、CRLF、BOM | `enc_audit.py` |
| F9 | 二次编码（mojibake） | 桥接逆向自检，CJK 占比回升 ≥0.10 | `enc_audit.py` |
| F10 | 零宽空格 / 不可见字符 | `U+200B/200C/200D/2060/FEFF/00AD` | `char_audit.py` |
| F11 | 双向控制符（Trojan Source） | `U+202A–202E / 2066–2069` | `char_audit.py` |
| F12 | 同形字冒充 ASCII | 西里尔 / 希腊 / 拉丁扩展映射表 | `char_audit.py` |
| F13 | 全角标点混入代码 | `U+FF01–FF5E`，且需在代码位置 | `char_audit.py` |
| F14 | 混合换行 / tab 空格混用 | CRLF+LF 并存、缩进内 tab+space | `char_audit.py` |

### 层 B · 结构层（脚本可判）

| 编号 | 问题 | 判据 | 脚本 |
|---|---|---|---|
| F3 | 漏写定义 | 改动前后定义名集合差（`LOST_DEF`） | `edit_guard.py` |
| F4 | 编造依赖 | `importlib.util.find_spec` / `node_modules` 实查 | `dep_check.py` |
| F5 | 同一段写两遍 | ≥5 行窗口重复 | `edit_guard.py` |
| F6 | 半成品占位符 | `TODO` / `stub` / `NotImplemented` / `pass` | `edit_guard.py` |
| F7 | 覆盖既有改动 | `--before` 对比 + 行数收缩（`SHRINK`） | `edit_guard.py` |

### 层 C · 语义层（**没有一行脚本能直接判**）

| 编号 | 问题 | 让它变可判的手段 |
|---|---|---|
| F15 | 同义反复测试 | 变异测试，mutation score ≥ 85% |
| F16 | 反向逻辑短路 | AST / CFG 真值表枚举 |
| F17 | 资源未释放 | 早退路径审计 + `Semgrep` 规则 |
| F18 | 并发泄漏 | goroutine 计数、`go test -race` |
| F19 | 边界缺失 | property-based testing（hypothesis / gopter） |
| F20 | 语义漂移 | 不变量闸、六边形边界测试 |
| F21 | slopsquatting 幻觉依赖 | 包年龄 / 下载量 / 仓库存在性校验 |

层 C 的检查器本项目**不提供**——写了也是假的。要真堵，得给项目配变异测试和真值表。

---

## 决定性证据：结构闸对不可见字符是瞎的

`stealth.js`：

```js
const role = "admin<U+200B>";
function isAdmin(u) { return u.role === role; }
```

- Node 实际输出 `false`
- `edit_guard.py` 只报 CRLF —— 语法通过、括号配平、定义齐全
- `char_audit.py` 定位到 `L1:20 U+200B`、`L5:12 U+00A0`

两个字符串打印一模一样，比较不等。换 JS / JSON / Markdown 更是一路静默通过。

**所以字符必须单独查一层。**

---

## 安装

作为 DSH / Claude Code 技能：

```bash
git clone https://github.com/wzs39/dsh-skill-edit-fidelity.git
cp -r dsh-skill-edit-fidelity ~/.dsh/skills/edit-fidelity
```

纯 Python 3.8+，无第三方依赖。

---

## 用法

### 一把过（推荐）

```bash
python scripts/audit_all.py target.py --before target.py.before
```

四道闸依次跑：`char` → `enc` → `guard` → `deps`。

```bash
python scripts/audit_all.py target.py --strict    # WARN 也算失败
python scripts/audit_all.py target.py --only char # 只跑字符层
python scripts/audit_all.py target.py --json      # 机器可读
```

### 单闸

```bash
# 字符层：零宽空格、同形字、全角、混合换行
python scripts/char_audit.py f.js --mode code
python scripts/char_audit.py f.js --fix              # 确定性映射，留 .bak
python scripts/char_audit.py f.py --fix-confusables  # 同形字改写需显式授权

# 结构层：截断、丢定义、占位符、写两遍
python scripts/edit_guard.py f.py --before f.py.before --strict

# 依赖层：import 了不存在的库
python scripts/dep_check.py f.py --root .

# 编码层：GBK / UTF-16 / BOM / mojibake
python scripts/enc_audit.py f.txt
python scripts/enc_audit.py f.txt --fix
python scripts/enc_audit.py f.txt --repair-mojibake

# 转义层：反斜杠计数
python scripts/bs_audit.py f.py --expect 18
python scripts/bs_audit.py f.py --has-literal snippet.txt

# 无转义写盘（base64 进，字节出）
python scripts/write_exact.py out.bin --b64-file payload.b64

# 环境体检：输出侧编码是不是 UTF-8
python scripts/enc_env.py
python scripts/enc_env.py --scan scripts
```

---

## 通道矩阵（本机实测）

| 通道 | 反斜杠保真 | 结论 |
|---|---|---|
| `write` 文件工具 | 1–6 个连续反斜杠逐字节保真 | 安全 |
| `edit` 文件工具 | `old_string` 含 3 个反斜杠精确命中 | 安全 |
| 命令行 `echo` / `heredoc` / `ops_bash` | 4 个反斜杠被压成 1 个 | **危险** |

结论：**危险通道是命令行，不是文件工具。** 含反斜杠的内容只走文件工具；必须在命令里出现时用 `chr(92)` 构造或 base64 + `write_exact.py`。

---

## 中文乱码先分清是哪一层

本机实测：console code page `936`，Python 在管道里默认按 `cp936` 编码输出，上层按 UTF-8 解码 → 中文乱。

| 方式 | 结果 |
|---|---|
| 默认（按 gbk 编码输出） | 6 个 U+FFFD 替换符 + `ABC`，即乱码 |
| `reconfigure(encoding="utf-8")` | `中文测试ABC` 正常 |

**乱码主因是输出侧，不是文件。** 脚本一律 `sys.stdout.reconfigure(encoding="utf-8")`，或设 `PYTHONUTF8=1`。

- `chcp 65001` 只改当前控制台显示，不改文件字节，不当修法用。
- 含 U+FFFD 的文件字节已在解码时丢失，**不可逆**，回源头重取。

---

## 抑制标记

文档、测试夹具、i18n 资源表会合法地包含乱码样本或不可见字符，否则检查器会把"举例说明乱码"的文档本身判成坏文件。

| 标记 | 作用域 | 用法 |
|---|---|---|
| `guard:ignore` | 单行 | 写在**被报的那一行**上（写在前一行无效） |
| `enc:ignore` | 单行 | 该行不参与 mojibake 判定 |
| `enc:ignore-file` | 整文件 | 整个文件跳过 mojibake 判定 |

源码里不写不可见字符的字面量，需要时用 `chr(0xAD)` 或 `bytes([...]).decode("latin-1")` 构造。

---

## 设计取舍

**全角标点要看词法位置。** 中文注释里的 `，。：` 是正常写作，代码位置才是缺陷。`char_audit.py` 用 `lex_mask()` 逐字符标出 代码/字符串/注释：注释内降为 `info`；字符串内只有 `FULLWIDTH` / `QUOTE` 降级——`U+200B` 在字符串里恰恰是真 bug，必须保留 `HIGH`。

**同形字默认只报告不改写。** 改它等于改标识符语义，需 `--fix-confusables` 显式授权。

**mojibake 判定用桥接逆向自检，不是猜。** `BRIDGES × TARGETS` 逆向，若 CJK 占比回升 ≥0.10 且 ≥0.5 才判二次编码。正常中文走桥接会 `UnicodeEncodeError`，故不误报。

**结构闸只借编译器间接发现不可见字符。** Python 会报 `invalid non-printable character U+200B`，JS / JSON / Markdown 不会。这是必须单开字符层的原因。

---

## 自审

本仓库所有文件对自己跑一遍：

```
SKILL.md                     PASS
scripts/audit_all.py         PASS
scripts/bs_audit.py          PASS
scripts/char_audit.py        PASS
scripts/dep_check.py         PASS
scripts/edit_guard.py        PASS
scripts/enc_audit.py         PASS
scripts/enc_env.py           PASS
scripts/write_exact.py       PASS
```

回归：5 个新造 mojibake 样本检出正确，正常中文零误报。

---

## 局限

- 层 C 七类语义缺陷**无法用本项目判定**，只能靠变异测试、真值表、race detector。
- `char_audit.py` 的 `lex_mask()` 是轻量词法扫描，不做完整语法解析；嵌套模板字符串等边界情况可能判错，宁可漏报不误报。
- `dep_check.py` 只查 Python / Node；其他语言按需扩展。
- `edit_guard.py` 的 `LOST_DEF` 依赖 `--before` 快照，没有快照时该闸不生效。

---

## License

MIT
