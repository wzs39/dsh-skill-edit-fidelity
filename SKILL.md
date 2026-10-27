---
name: edit-fidelity
description: 防止编辑/写入文件时字符被吞、内容被截断、定义被漏写、依赖被编造、代码语义写反，并在写完后用字节与结构证据核对。当出现以下情况时加载：反斜杠被吞、转义丢失、多了一层转义、edit 报 string not found、代码写漏写错、函数写一半、文件被截断、括号不配平、import 了不存在的库、同一段代码写了两遍、留下 TODO/占位符、改动把原有函数弄丢、Windows 路径 C:\ 变成 C:、heredoc 或 echo 写出乱码、两个看起来一样的字符串却不相等、中文乱码、零宽空格、不可见字符、同形字、全角标点、弯引号、混合换行、tab 空格混用、Trojan Source、条件写反、资源没关、测试全绿但实现改坏仍通过。也用于 backslash swallowed, escaping lost, double escaping, edit tool string not found, code truncated, missing function after edit, hallucinated import, duplicated block, placeholder left behind, invisible characters, zero width space, homoglyph, fullwidth punctuation, mixed line endings, inverted logic, tautological test。在写含转义字符的代码、做大范围改写、或交付前核对时加载。
---

<!-- enc:ignore-file 本文档要举例说明 mojibake，正文含样本字符串，请勿对本文件做二次编码判定 -->

# edit-fidelity：编辑保真（字节 + 结构 + 语义）

## 1. 核心判断

"AI 写错、漏写"不是一种病，是**二十一种可分别检测的失败**，分三层：

| 层 | 失败数 | 判据来源 | 谁判 |
| --- | --- | --- | --- |
| A 字节层 | F1–F2、F8–F14 | 原始字节、码点 | 脚本一跑就出结论 |
| B 结构层 | F3–F7 | 语法树、定义集合 | 脚本一跑就出结论 |
| C 语义层 | F15–F21 | 行为、不变量、测试是否真能失败 | **脚本只能提示，必须靠测试与审查** |

关键认知：**A、B 两层能被机械否掉，C 层不能。** 所以 C 层的对策不是"再仔细一点"，而是换成能被证伪的手段（变异测试、属性测试、真值表、不变量闸）。

判据一律从字节、结构、可执行行为里取，不从模型的自我声明里取。

## 2. 失败模式目录

### 层 A：字节层

| # | 失败 | 典型表现 | 机械判据 | 检测 |
| --- | --- | --- | --- | --- |
| F1 | 转义被吞 / 加倍 | 反斜杠少一层或多一层 | 反斜杠字节计数、逐行计数 | `bs_audit.py --expect N` |
| F2 | 截断 | 文件写到一半、末尾断在 `:` `(` `,` | 真解析失败、末尾符号悬空、非空行骤降 | `edit_guard.py`（SYNTAX/TRUNCATE） |
| F8 | 编码/换行破坏 | CRLF 混入、BOM、中文乱码 | 字节标记、控制台编码 | `enc_audit.py` / `enc_env.py` |
| F9 | 二次编码（mojibake） | `ä¸­æ–‡`、`杩欐槸`、`锟斤拷`、U+FFFD 替换符 | 桥接逆向自检、U+FFFD 检测 | `enc_audit.py --repair-mojibake` |
| F10 | 不可见字符 | 字符串比较莫名失败、搜索找不到 | 码点表：U+200B/200C/200D/2060/00AD/FEFF | `char_audit.py`（INVISIBLE） |
| F11 | 双向控制符（Trojan Source） | 源码显示顺序与编译顺序不一致 | U+202A–202E、U+2066–2069、U+200E/200F | `char_audit.py`（BIDI） |
| F12 | 同形字冒充 | 标识符看起来是 `name`，实际含西里尔 `а` | 上形字映射表 | `char_audit.py`（CONFUSABLE） |
| F13 | 全角标点 / 弯引号 | 中文输入法带进 `（）` `，` `“”` | U+FF01–FF5E、U+2018–201F | `char_audit.py`（FULLWIDTH/QUOTE） |
| F14 | 混合换行 / 混合缩进 | CRLF 与 LF 混排、tab 与空格混排 | 换行字节统计、行首空白构成 | `char_audit.py`（MIXED_EOL/MIXED_INDENT） |

F10 的杀伤力实测（本机 `stealth.js`）：

```js
const role = "admin\u200B";        // 字面量尾部藏了一个零宽空格
function isAdmin(u) { return u.role === role; }
console.log(isAdmin({role: "admin"}));
```

Node 输出 `false`。人眼读源码完全看不出问题；`edit_guard.py` 只报了一条 CRLF（**结构层对它是瞎的**）；`char_audit.py` 直接定位到 `L1:20 U+200B`。这类"看起来一样却不相等"只有码点层能判。

### 层 B：结构层

| # | 失败 | 典型表现 | 机械判据 | 检测 |
| --- | --- | --- | --- | --- |
| F3 | 漏写定义 | 改完 `merge()` 没了 | 改动前后定义名集合差 | `edit_guard.py --before`（LOST_DEF） |
| F4 | 编造依赖 | `import 不存在的库` / 引用不存在的文件 | 模块可解析性、路径存在性 | `dep_check.py` |
| F5 | 写两遍 | 同一段逻辑出现两次 | 连续 ≥5 行窗口重复 | `edit_guard.py`（DUP_BLOCK） |
| F6 | 半成品 | `TODO` / `...` / `NotImplementedError` / `pass` 占位 | 占位符词表 | `edit_guard.py`（PLACEHOLDER） |
| F7 | 覆盖既有改动 | 整文件 write 冲掉没读过的部分 | 只增不减校验、定义差集、非空行骤降 | `edit_guard.py --before` |

### 层 C：语义层

这一层**没有一行脚本能直接判**。下表给的是"如何让它变得可判"。

| # | 失败 | 典型表现 | 怎么让它可判 |
| --- | --- | --- | --- |
| F15 | 同义反复测试 | 断言等于 mock 返回值；改坏实现测试仍绿 | **变异测试**：注入 AOR/ROR/COR/SDL 变异体，测试全绿即同义反复。门限 mutation score ≥ 85% |
| F16 | 反向逻辑 / 短路错误 | `if (!u.isActive \|\| !u.isAdmin) { return nil }` 让非活跃非管理员直接通过 | 条件真值表枚举；AST/CFG 校验；对授权类函数写"必须拒绝"的负例测试 |
| F17 | 资源未释放 | 早退路径不 `close` body、不回滚事务，连接池耗尽 | 每条 `return err` 路径上的资源配对检查；Semgrep 类规则（未 defer close / 未 rollback） |
| F18 | 并发泄漏 | goroutine 无 context 超时、无 WaitGroup 跟踪、无缓冲 channel 发送永久阻塞 | 测试前后 `runtime.NumGoroutine()` 计数差；`-race`；带超时的 context 强制要求 |
| F19 | 边界条件缺失 | `limit <= 0`、`offset + limit` 溢出、空集合、时区/闰秒 | **属性测试**（hypothesis / gopter / fast-check）喂 0、负数、MAX_INT、畸形 UTF-8 |
| F20 | 语义漂移 / 不变量侵蚀 | 为通过 guest checkout 放松 `UserID` 非空，下游报税崩 | 不变量闸：核心模型约束变更必须单独提交；schema 校验在 CI 拒收 |
| F21 | 幻觉依赖（slopsquatting） | 包名真的存在，但是攻击者按模型幻觉抢注的 | 新增依赖查包年龄/下载量/仓库活跃度；只允许走内部代理；锁文件比对 |

F16 的真实形状（不要只看一眼就放过）：

```go
func checkAdminAccess(u *User) error {
    if !u.IsActive || !u.IsAdmin {   // 意图是"拒绝非活跃或非管理员"
        return nil                    // 实际是"非活跃 或 非管理员 都放行"
    }
    return errors.New("unauthorized")
}
```

正确写法应是 `if !(u.IsActive && u.IsAdmin) { return errDenied }`。**德摩根律写反是 AI 的高频错误**，因为它在语法上完美、在评审时"读起来顺"。

### 层 C 的审查纪律

1. **越漂亮越可疑**：语法优雅是 token 概率的产物，不是正确性证据。先看边界、空值、错误返回。
2. **审"缺什么"而不是"有什么"**：超时、限流、context 取消、背压、事务回滚 —— 这些是模型系统性省略的东西。
3. **反演测试**：把 `if balance > 0` 改成 `if balance < 0`，测试仍绿就说明测试是假的。
4. **限 diff 规模**：单次改动超过 400 行就拆。大 diff 必然稀释审查注意力。

F1 的层归因（哪一层吃掉的）：

| 层 | 现象 | 处理 |
| --- | --- | --- |
| L1 模型生成 | 该写两层只写一层 | 先读后改，不凭记忆重建 |
| L2 工具参数（JSON） | 少/多一层 | 走文件工具，内容当原文写 |
| L3 命令行 / Shell | 4 个反斜杠只剩 1 个 | 禁止命令生成代码；用 `chr(92)` 或 base64 |
| L4 程序内字面量 | 文件对、行为错（`"\d"` 退化） | 原始字符串、字符类、`json.dumps` |
| L5 文件系统 | `C:\x` 变 `C:x` | 路径统一 `/` |

实测：`write` 与 `edit` 对 1–6 个连续反斜杠逐字节保真；`ops_bash` 命令串把 4 个压成 1 个。**所以危险的是命令通道，不是文件工具。**

## 3. 硬规则

1. **先读后改**：`old_string` 必须来自刚读到的真实文本，禁止凭记忆重建。
2. **含转义的内容只走 `write` / `edit`**，这是唯一可信通道。
3. **禁止用命令写代码**：`echo`、`printf`、`cat <<EOF`、`sed -i`、`Set-Content` 一律不用来生成含反斜杠的代码。
4. **命令里必须有反斜杠时用构造式**：Python `chr(92)`、JS `String.fromCharCode(92)`、bash `$'\134'`，或 base64 + `write_exact.py`。
5. **能不用反斜杠就不用**：路径用 `/`；正则用原始字符串或 `[.]`；JSON 用 `json.dumps`；SQL 参数化。
6. **改前先留快照**：`cp target target.before`，改完必须 `--before` 对比。没有 before 就没有 F3/F7 的判据。
7. **一次只改一处**：大改拆成多次小 `edit`。整文件重写是 F3/F7 的主要来源。
8. **只增不减**：除非明确要删，改动不应让定义集合变小、非空行骤降。
9. **`edit` 报 not found 时**：重新 `read`，把 `old_string` 缩到唯一短锚点。禁止因匹配失败就整文件重写。
10. **不编造依赖**：写 `import` / `require` / 路径前，先确认它在环境里存在；写完跑 `dep_check.py`。
11. **不留占位符**：交付物里出现 `TODO` / `...` / `NotImplementedError` 就算没写完，要么实现，要么明说这是未完成项。
12. **不要为了"看起来对"而重排文件**：格式化、换行符、BOM 变化会掩盖真实差异。
13. **代码里不出现全角标点与弯引号**：`（）` `，` `；` `“”` `‘’` 只在正文里合法。写代码前切英文输入法，写完跑 `char_audit.py`。
14. **字符串比较莫名失败时先查码点**：不怀疑逻辑，先 `char_audit.py` 看有没有 U+200B / U+00A0 / 同形字。
15. **不引入不可见字符**：零宽空格、软连字符、行中 BOM 没有一个是"不小心放对了"的场景，一律删除。
16. **交付前四道闸全过**：字节 → 字符 → 结构 → 依赖。只过语法只能证明"没截断"。
17. **层 C 的东西不靠声明，靠证伪**：说"逻辑对"要有负例测试；说"测试有效"要有变异分数；说"并发安全"要有 `-race` 与 goroutine 计数。
18. **脚本对反斜杠字符本身零字面量**：需要反斜杠字符时用 `chr(92)`；正则里的 `[ \t]` 属于单层转义，保留。这样脚本不会被转义层破坏，可当参考实现。
19. **改完脚本要真跑一次 `--help`**：`py_compile` 只查语法，查不出模块级运行时错误。实测 `set(...) + {""}` 语法完全合法，一 import 就 `TypeError: unsupported operand type(s) for +: 'set' and 'set'`。
20. **检查器报错先怀疑检查器**：语法已通过时，配平、占位符、全角标点这类告警多半是词法器误判，不是代码错。见第 12 节。
21. **字节判据不用 shell 转义**：`grep -c $'\r'` 在部分 shell 里被当成字面 `r`，返回等于总行数的假阳性。数 `\r\n` 一律用 Python 读 bytes。
22. **工具不能自带它要检查的缺陷**：一个查混合换行的仓库，`.gitattributes` 必须写 `* text=auto eol=lf`，否则 `core.autocrlf` 把工作树转成 CRLF，工具自己先犯它要查的病。

## 4. 通道选择矩阵

| 内容类型 | 首选 | 备选 | 禁止 |
| --- | --- | --- | --- |
| 普通源码、配置、Markdown | `write` / `edit` | — | 命令行重定向 |
| 正则、LaTeX、C/JS 字符串、JSON-in-JSON | `write` / `edit` | base64 + `write_exact.py` | `echo` / heredoc |
| 命令里必须带反斜杠的片段 | `chr(92)` 构造 | base64 + `--from-file` | 裸写字面反斜杠 |
| Windows 路径 | `/` 分隔 或 `pathlib` | 原生反斜杠仅限文件工具参数 | 命令里裸写 |
| 二进制 / 精确字节 | `write_exact.py --b64` | `--from-file` | 文本工具 |
| 含中文的正文 | `write` / `edit` | — | 命令里写中文字面量 |

## 5. 改动协议（标准四步）

```bash
S=~/.dsh/skills/edit-fidelity/scripts

# 1. 快照
cp target.py target.py.before

# 2. 改（用 write/edit 工具，不用命令）

# 3. 一次跑完四道闸
python $S/audit_all.py target.py --before target.py.before

# 4. 只看某一闸 / 补字节断言
python $S/audit_all.py target.py --only char,guard
python $S/bs_audit.py target.py --expect N        # 仅当文件含转义字符
```

`audit_all.py` 汇总四闸并给统一 `verdict`，退出码 0 全过、1 有失败。判定：`verdict = PASS` 才算完成。

## 6. 字符层：不可见字符与同形字

```bash
S=~/.dsh/skills/edit-fidelity/scripts
python $S/char_audit.py F                 # auto 模式（按扩展名判 code/text）
python $S/char_audit.py F --mode code     # 强制按代码判
python $S/char_audit.py F --fix           # 清理不可见/双向/空格/全角/引号（留 .bak）
python $S/char_audit.py DIR --recursive   # 整目录体检
python $S/char_audit.py F --verbose       # 展开 low/info
```

严重度与模式的关系（**这是关键设计**：中文正文里的全角标点是合法的，不能误报）：

| 类别 | code 模式 | text 模式 | 理由 |
| --- | --- | --- | --- |
| BIDI | critical | critical | Trojan Source，任何上下文都是攻击面 |
| INVISIBLE | high | medium | 零宽字符没有正当用途 |
| SPACE 仿冒 | high | medium | NBSP/U+3000 在字符串里不匹配普通空格 |
| QUOTE 弯引号 | high | low | 代码里不是定界符；正文里正常 |
| FULLWIDTH 全角 | high | info | 代码里非法 token；中文正文必需 |
| CONFUSABLE 同形字 | critical | low | 标识符冒充；正常外文正文里可能是真字母 |

`--fix` 只做确定性映射（删除不可见、空格归一、全角转 ASCII、弯引号转直引号），**同形字默认只报告不改写**——改它等于改标识符语义，必须 `--fix-confusables` 显式授权。

## 7. 中文编码：先分清"文件坏了"还是"显示层坏了"

实测本机（Windows + DSH 管道）：

```
console code page   = 936 (GBK)
sys.stdout.encoding = gbk        # 未修正时
stdout.isatty       = False      # 管道
preferred encoding  = cp936
```

同一句中文三种输出方式，只有一种正常：

| 方式 | 结果 |
| --- | --- |
| 默认（按 gbk 编码输出） | 6 个 U+FFFD 替换符 + `ABC`，即乱码 |
| `reconfigure(encoding="utf-8")` | `中文测试ABC` 正常 |
| 显式 gbk 输出 | 乱码 |

**结论：上层按 UTF-8 解码，Python 在 Windows 管道里默认按 cp936 编码。** 所以乱码的主因是输出侧，不是文件。

分层：

| 层 | 现象 | 判据 | 修法 |
| --- | --- | --- | --- |
| E1 输出侧 | 程序跑对了，打印出来是乱码 | `stdout.encoding` 不是 utf-8 | 脚本开头 `reconfigure(encoding="utf-8")`；或 `PYTHONUTF8=1` |
| E2 文件编码 | 文件真是 GBK / UTF-16 / 带 BOM | `enc_audit.py` 判出非 utf-8 | `enc_audit.py --fix`（留 .bak） |
| E3 二次编码 | 文件是合法 UTF-8，但内容是 `ä¸­æ–‡` | CJK 占比桥接逆向回升；或含 U+FFFD | `--repair-mojibake`；U+FFFD 不可逆，回源头重取 |
| E4 通道 | 命令里写中文字面量 | `echo`/`printf` 落盘字节随代码页变 | 中文内容只走 `write` / `edit` |
| E5 字体 | 只有个别符号显示成方框 | 文件字节正确 | 换字体，不是编码问题 |

```bash
python $S/enc_env.py                      # E1：看 stdout 是否 utf-8
python $S/enc_audit.py F                  # E2/E3：这文件到底是什么编码
python $S/enc_audit.py F --fix --repair-mojibake   # 转 UTF-8 无 BOM + 还原二次编码
python $S/enc_audit.py DIR --recursive    # 整目录体检
```

`enc_audit.py` 的判定顺序（先强证据后弱猜测）：BOM → 大量 NUL → 严格 UTF-8 → GB18030 + CJK 占比 → unknown。
`--fix` 只改编码，不动换行（CRLF 保留），并留 `.bak`。

## 8. 验证四档

```bash
# A 字节级（转义类必做）
python $S/bs_audit.py F --expect N
python $S/bs_audit.py F --has-literal lit.txt

# B 字符级（任何含非 ASCII 的改动都做）
python $S/char_audit.py F --mode code

# C 结构级（任何改动都做）
python $S/edit_guard.py F [--before F.before] [--strict]

# D 依赖与语义
python $S/dep_check.py F --root .
python -m py_compile F    # 或 node --check / jq . / bash -n
```

`edit_guard.py` 输出 `verdict` + 逐条 `[FAIL]/[WARN]` 带行号，`--json` 给机器读。
`--strict` 把 WARN 也算失败，适合交付前最后一跑。

层 C 的验证不是脚本，是这几条命令（按语言选）：

```bash
python -m pytest --count=1                  # pytest-repeat：顺序依赖
go test -race ./...                         # F18
python -m pytest --hypothesis-show-statistics   # F19
mutmut run / go-mutesting / stryker run      # F15：mutation score
```

## 9. 修复流程

1. 跑 `audit_all.py` 拿到哪一闸失败、哪一行。
2. 字节/字符类：`bs_audit.py` + `char_audit.py --verbose` + `repr()` 看真实码点。
3. 定点 `edit` 补回，**不整文件重写**。
4. 重跑第 8 节 A+B+C+D。
5. 同一文件反复出错 → 改成"生成到临时文件 → 核对 → `--from-file` 覆盖"。
6. 层 C 的问题 → 先补一个能失败的测试，再改实现。测试先绿后改是 F15 的温床。

## 10. 常见误判

- **"模型写错了"**：先看是不是命令通道吞的。同一模型走 `write` 往往是对的。
- **"多加一层转义更安全"**：多写一层就是多一个字节，内容直接错。
- **"语法通过就行"**：`"\d"` 多数语言不报错但语义已错；语法只证明没截断。
- **"文件行数没变就没事"**：可能整段被同长度内容替换（F7），要看定义集合。
- **"两个字符串看着一样就是一样"**：先查码点。U+200B/U+00A0/西里尔 `а` 全都长得一样但 `!=`。
- **"语法检查过了就没有隐藏字符"**：`stealth.js` 实测——含 ZWSP 的字符串字面量语法完全合法，`node --check` 与 `edit_guard` 都放行，运行时行为却错。
- **"测试全绿所以逻辑对"**：同义反复测试（F15）永远绿。用变异测试验证测试本身。
- **"中文乱码是文件坏了"**：先跑 `enc_env.py` 看 `stdout.encoding`。本机实测乱码来自输出侧 cp936，文件本身是好的 UTF-8。
- **"改 chcp 65001 就能修好"**：只影响该控制台，不改文件字节，也不改已落盘的 GBK 内容。
- **"乱码文件转成 UTF-8 就好"**：`ä¸­æ–‡` 这类要 `--repair-mojibake`；含 U+FFFD 替换符的字节已丢，转不回来。（本文档刻意不嵌入那个字形本身——否则检查器会把文档自己判成 mojibake。）
- **"重复代码是巧合"**：连续 5 行完全一致几乎只有"写两遍"一种来源。
- **"代码好看就是写得好"**：语法优雅是 token 概率产物。先看边界、空值、错误路径。
- **"检查器报错就是代码错"**：先看第 12 节。实测一次 482 条 FULLWIDTH 告警全是误报，根因是词法器不认正则字面量里的反引号。
- **"扫描器说括号不配平就是真不配平"**：`node --check` / `python -c compile` 通过就必然配平。扫描器错，不是代码错。
- **"占位符告警就是没写完"**：检查器自己的检测逻辑里必然含 `TODO` 这类字面量，会被自己抓到。看行内容再判。
- **"py_compile 过了脚本就能跑"**：只查语法。`set(...) + {...}` 语法合法，一 import 就 TypeError。
- **"grep 数换行能验 LF"**：`grep -c $'\r'` 在部分 shell 里把 `$'\r'` 当字面 `r`，返回等于总行数的假阳性。用 Python 读 bytes 数 `\r\n`。

## 11. 脚本

| 脚本 | 层 | 作用 |
| --- | --- | --- |
| `scripts/audit_all.py` | 汇总 | 一次跑 char/enc/guard/deps 四闸，统一 verdict；`--before` / `--only` / `--skip` / `--strict` / `--json` / `--script-body` |
| `scripts/bs_audit.py` | A | 反斜杠总数/成对/单发、逐行计数、CRLF/BOM/尾换行、sha256；`--expect` / `--has-literal` |
| `scripts/char_audit.py` | A | 不可见字符、双向控制符、同形字、全角标点、弯引号、混合换行、混合缩进、控制字符；`--fix` / `--fix-confusables` / `--mode` / `--recursive` |
| `scripts/enc_audit.py` | A | BOM / UTF-16 / 严格 UTF-8 / GB18030 判定、mojibake 桥接自检、U+FFFD 检测；`--fix` / `--repair-mojibake` |
| `scripts/enc_env.py` | A | console code page、`stdout.encoding`、`PYTHONUTF8` 等；`--scan DIR` 找缺 UTF-8 修正的脚本 |
| `scripts/edit_guard.py` | B | SYNTAX、BALANCE、TRUNCATE、LOST_DEF、PLACEHOLDER、DUP_BLOCK、ENCODING、SHRINK；`--script-body` |
| `scripts/dep_check.py` | B | Python `import` 可解析性、Node 相对路径与裸包存在性 |
| `scripts/write_exact.py` | — | 无转义写入：`--b64` / `--b64-file` / `--from-file`，输出 sha256 |

`edit_guard.py` 行内加 `guard:ignore` 可抑制该行的占位符判定（用于文档、词表、检查器自身）。**注释必须写在被抑制的那一行本身**——写在 `except` 行对下一行的 `pass` 无效。

`--script-body`：顶层含 `return` 的 JS（workflow 脚本、函数体片段）直接 `node --check` 必报 `Illegal return statement`。加这个开关会把内容包成 `async function __script_body__(){...}` 再校验，报错路径显示为 `<script-body>`。

```bash
python $S/audit_all.py scripts/task.workflow.mjs --script-body
```

八个脚本需要反斜杠字符时一律用 `chr(92)`，统一 UTF-8 输出（Windows 控制台不再乱码），可 `py_compile` 自检；对自身跑 `edit_guard.py --strict` 全部 PASS。

## 12. 检查器自身的失败模式

这些是实测撞出来的。检查器给 FAIL 时，先按本节排除它自己错，再去改代码。

| 编号 | 症状 | 根因 | 修法 |
| --- | --- | --- | --- |
| L1 | 满屏 FULLWIDTH / QUOTE 告警，全在中文字符串里 | 词法器不认正则字面量。`/[^\s"'` + 反引号 + `，。；、）)]+/` 这类字符类里含引号，被当成字符串开头，**后续整文件掩码错位** | 加 `regex_allowed()`：回看前一有效字符（`=(,:[!&|?{};+-*%<>~^`）或关键字（`return`/`typeof`/`case`/`in`/`of`/`delete`/`void`/`new`/`do`/`else`）判定，正则正文按字面量标 |
| L2 | `多余的 }`、`未闭合符号`，行号指向空白行 | 多行反引号模板在换行处被截断，模板正文当代码扫；`/* */` 块注释没跳过 | 反引号跨行继续（`line += 1`）、`/*` 找 `*/` 并累加行号 |
| L3 | 语法检查明明通过，结构闸还报不配平 | 逐字符扫描器追不全 JS 语法，却去否决真解析器 | **启发式不许否决解析器**：`ok is True` 时降 INFO 并注明「语法已通过，判为扫描器误判」，只有无解析器或解析失败才 FAIL |
| L4 | 检查器自己被抓：`PLACEHOLDER_RE = /…|TODO|…/` 报占位符；`except: pass` 报 stub | 自指误报——检测逻辑里必然含它要检测的字面量 | 词表/定义行自动跳过；`guard:ignore` 写在目标行本身 |

**判定顺序**（L1 那条踩过两次）：
1. 注释先判，正则后判。反过来 `//` 会被当正则开头，一路吞到下一个 `/`，整段括号算错。
2. 字符串先判，正则后判。字符串里的 `/` 不是正则。
3. 语法结果最后用，用来决定配平告警的严重度。

**怎么发现检查器错了**：
- 造正负控制样本：一个确定干净的、一个确定坏的。两边结论都对，才谈得上判中间态。
- 同一文件换模式（`--mode code` / `text`）看结论是否翻转。翻转说明判据依赖模式而非事实。
- 语法通过但结构告警 → 优先怀疑扫描器，不是代码。
- 告警集中在某一类字符、某一段区间 → 多半是掩码从那里开始错位。

**这条经验是通用的**：任何"我写了个检查器"的场合，先问它认不认正则、模板、块注释、注释里的引号。词法器不完整时，误报比漏报更伤——漏报你还知道自己没查，误报会让你去改本来对的代码。

