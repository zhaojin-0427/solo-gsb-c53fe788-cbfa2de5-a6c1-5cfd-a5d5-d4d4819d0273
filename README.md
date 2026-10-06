# DICOM 研究数据匿名化 API

基于 **Python + FastAPI + SQLite + pydicom + Pillow** 的 DICOM 研究数据匿名化服务。
客户端提交含多序列的 DICOM ZIP、版本化匿名化策略和可选像素遮挡框，服务输出
**确定性、可复验**的匿名化结果。

## 特性

- **确定性 UID 映射**：按 Study/Series/Instance 关系，用 HMAC-SHA256 将原始 UID
  映射为 `2.25.<decimal>` 形式的新 UID；同一 UID 在所有实例及引用处
  （`ReferencedSOPInstanceUID` 等）一致替换，保持引用完整性。
- **PHI 清除（覆盖所有 SQ 层级）**：内置类 DICOM PS3.15 基本档案（姓名、出生日期、
  机构、医师、入组号等置空，`PatientID` 哈希化），默认删除全部私有标签；
  默认动作与策略中的 `empty`/`remove`/`hash`/`replace` 动作按同一策略递归作用于
  **顶层数据集及保留下来的每一层序列项（含嵌套 SQ）**。策略整条移除某个序列时，
  其子项不再被处理或计数；`empty` 一个序列则保留空序列壳。策略可增删改。
- **日期重写且保持时间差**：按患者派生确定性偏移（天数 + 秒级抖动），
  所有 DA/TM/DT 标签同步平移，跨实例时间差逐秒保持。
- **像素遮挡**：按遮挡框（instance/series/study 三级作用域）真正覆写像素
  （Pillow），支持 8/16 位灰度与 8 位交错 RGB，覆写后统一以
  Explicit VR Little Endian 重新编码。
- **字节级确定性**：相同输入 + 相同策略 ⇒ 输出 ZIP 字节完全一致
  （固定 ZIP 时间戳、确定性文件命名、确定性 DICOM 编码、HMAC 派生映射）。
- **全有或全无**：缺失引用、非法 VR、压缩像素、策略冲突等逐项报告，
  任一错误即整体失败，绝不产出半成品。
- **审计与可复验哈希**：结果附审计摘要（统计、UID 映射、警告、密钥指纹）及
  输出 ZIP 与逐文件 SHA-256；ZIP 内含 `manifest.json` 供离线复验。
- **幂等提交按密钥作用域隔离**：相同输入 + 策略在**同一 `ANON_SECRET`** 下
  重复提交返回同一作业（HTTP 200）；轮换密钥后原样重提会得到**独立的新作业、
  审计与结果哈希**，绝不会把旧密钥的产物当作新密钥的结果返回。

## 快速开始（Docker Compose）

```bash
docker compose up --build
```

服务监听 <http://localhost:8000>：

- 交互式 API 文档：<http://localhost:8000/docs>
- 健康检查：`GET /healthz`
- 策略说明：`GET /policies`

作业库（SQLite）与结果 ZIP 持久化在命名卷 `dicom-anon-data`（容器内
`/data`），重启容器不会丢失；下文的密钥轮换演练正是在这份持久化数据上进行。

> 生产部署请设置稳定的 `ANON_SECRET`（环境变量或 `.env` 文件），
> 它是 UID 映射 / 日期偏移 / 哈希的 HMAC 根密钥；变更后映射结果会改变。
> 服务只持久化密钥的 **SHA-256 指纹**（见下文「密钥轮换」），永不保存明文。

## 本地开发

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
pytest tests/ -q          # 35 项测试（含密钥轮换与旧库迁移）
```

## 示例请求

### 1. 生成示例数据（1 个检查 × 2 个序列 × 2 个实例，含模拟 PHI）

```bash
python scripts/make_sample.py          # 生成字节确定的 sample_input.zip
```

每个实例除顶层 PHI 外还携带：

- 一棵**保留的多层序列树**
  `VerifyingObserverSequence → OriginalAttributesSequence → OriginalAttributesSequence`，
  各层都含 `PatientName`/`InstitutionName` 等 PHI、一个私有标签，叶节点含
  `ReferencedSOPSequence`（指向包内其他实例）；
- 一棵 `RequestAttributesSequence`，其子项同样含多层 PHI——示例策略会把它整条移除。

ZIP 使用固定条目顺序与 1980-01-01 时间戳写入，重新生成逐字节一致。

### 2. 提交匿名化作业

```bash
curl -s -X POST http://localhost:8000/jobs \
  -F "file=@sample_input.zip" \
  -F "policy=<examples/policy.json" \
  -F "redactions=<examples/redactions.json"
```

响应（HTTP 202；同一密钥下重复提交返回 200 与同一 `job_id`）：

```json
{
  "job_id": "3c9dbb7bdbef949d934381f8733e2c1e",
  "status": "queued",
  "status_url": "/jobs/3c9dbb7bdbef949d934381f8733e2c1e",
  "detail": null,
  "key_fingerprint": "c5c66dd438c0ba919018ab9a3bd2314610848dc84b2cd59b0d6a09ccb27c3b05"
}
```

`key_fingerprint` 是当前 `ANON_SECRET` 的 SHA-256 指纹（非明文密钥）：
作业判重与引擎 HMAC 用的是同一个密钥作用域。

> 下列示例数值用 `docker compose` 的默认 `ANON_SECRET=change-me-in-production`
> 实跑采集；设置了其他密钥时 `job_id`、指纹、映射 UID 与哈希会不同。重新生成的
> `sample_input.zip` 与示例策略字节固定，所以同一密钥下结果可逐字节复验。

### 3. 查询状态与审计摘要

```bash
curl -s http://localhost:8000/jobs/<job_id>
```

成功时（节选，来自对 `sample_input.zip` + `examples/policy.json` 的真实调用）：

```json
{
  "job_id": "3c9dbb7bdbef949d934381f8733e2c1e",
  "status": "done",
  "policy_version": "1.0",
  "policy_sha256": "1c0d2dd6424dc99a890d877fd54488fca69367c8eea49437ed191c79b37d8175",
  "input_sha256": "2bcc31fa707c4b9c50a71781cde5a2b24abe9dd20ded1eb0b651bf222760739e",
  "key_fingerprint": "c5c66dd438c0ba919018ab9a3bd2314610848dc84b2cd59b0d6a09ccb27c3b05",
  "audit": {
    "key_fingerprint": "c5c66dd438c0ba919018ab9a3bd2314610848dc84b2cd59b0d6a09ccb27c3b05",
    "summary": { "studies": 1, "series": 2, "instances": 4,
                 "uids_mapped": 7, "tags_removed": 4, "tags_emptied": 52,
                 "tags_replaced": 8, "tags_hashed": 4,
                 "private_tags_removed": 12, "date_tags_shifted": 16,
                 "redaction_boxes_applied": 2 },
    "uid_mapping": {
      "1.2.826.0.1.3680043.9.7433.1.1":     "2.25.303989340376998048752381211511128573336",
      "1.2.826.0.1.3680043.9.7433.1.1.1":   "2.25.93670731803630432347505141810977829969"
    },
    "output": { "zip_sha256": "855651eb6aa3d79d1a85c36e4ff4feb63642bc5ee9b4d48304799b9e4b96566d",
                "files": [
      { "path": "STUDY_0001/SERIES_0001/INSTANCE_00001.dcm",
        "sha256": "02d822b43a7cb63f0e04eb80e0564eeb8a855220fa8f698e56de4cd7811efa97",
        "study_instance_uid":  "2.25.303989340376998048752381211511128573336",
        "series_instance_uid": "2.25.93670731803630432347505141810977829969",
        "sop_instance_uid":    "2.25.145337988595756024462092823072960691239" } ] }
  },
  "result": { "sha256": "855651eb6aa3d79d1a85c36e4ff4feb63642bc5ee9b4d48304799b9e4b96566d",
              "size_bytes": 16045,
              "download_url": "/jobs/3c9dbb7bdbef949d934381f8733e2c1e/download" }
}
```

上述计数体现递归处理：`tags_removed=4` 即 4 个实例各移除 1 个
`RequestAttributesSequence`，其子树（`PatientName`、私有标签、额外 UID 等）
不再处理也不计入 `tags_emptied`/`private_tags_removed`/`uids_mapped`；
保留的 `VerifyingObserverSequence` 三层项内 PHI 均被清空、叶节点引用 UID
被一致重映射，序列层级结构原样保留。

失败时（逐项错误，无半成品；非法 VR / 非法值即使位于 SQ 项内也按标签逐项报告）：

```json
{ "job_id": "89468715c44f29e4e5cf1733d29f3782", "status": "failed",
  "errors": [
    { "file": "compressed.dcm", "code": "COMPRESSED_PIXELS",
      "message": "compressed transfer syntax 1.2.840.10008.1.2.4.50 is not supported; …",
      "tag": null } ],
  "audit": null, "result": null }
```

### 4. 下载并复验

```bash
curl -s -OJ http://localhost:8000/jobs/3c9dbb7bdbef949d934381f8733e2c1e/download
sha256sum anonymized-3c9dbb7bdbef949d934381f8733e2c1e.zip
# 855651eb…6566d  anonymized-…zip  —— 与 result.sha256 / audit.output.zip_sha256 一致
unzip -p anonymized-3c9dbb7bdbef949d934381f8733e2c1e.zip manifest.json   # 逐文件 SHA-256、映射后 UID 与 key_fingerprint
```

可用 pydicom 直接确认多层 SQ 的清洗结果：

```python
from pydicom import dcmread
import io, zipfile
zf = zipfile.ZipFile("anonymized-3c9dbb7bdbef949d934381f8733e2c1e.zip")
ds = dcmread(io.BytesIO(zf.read("STUDY_0001/SERIES_0001/INSTANCE_00001.dcm")))
assert "RequestAttributesSequence" not in ds                 # 整条移除
leaf = (ds.VerifyingObserverSequence[0]
          .OriginalAttributesSequence[0]
          .OriginalAttributesSequence[0])
assert leaf.PatientName == "" and leaf.InstitutionName == "" # 深层 PHI 已清空
assert str(leaf.ReferencedSOPSequence[0].ReferencedSOPInstanceUID).startswith("2.25.")
```

## API 一览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `POST` | `/jobs` | 提交作业（multipart：`file` ZIP、`policy` JSON 字符串、`redactions` 可选 JSON 数组）。幂等：**同一 `ANON_SECRET`** 下相同输入返回既有作业（200），换密钥则另开新作业（202） |
| `GET` | `/jobs/{id}` | 查询状态 / 逐项错误 / 审计摘要 / 结果哈希 / 密钥指纹 |
| `GET` | `/jobs/{id}/download` | 下载匿名化结果 ZIP（未完成返回 409，作业不存在返回 404） |
| `GET` | `/policies` | 支持的策略版本、默认档案、遮挡框格式 |
| `GET` | `/healthz` | 健康检查 |

## 密钥轮换演练（持久化数据，可直接复验）

作业 ID 与判重均以**密钥作用域**为准。作业 ID 为

```
sha256("dicom-anon-job:v2|" + key_fingerprint + "|" + input_sha256
       + "|" + canonical(policy) + "|" + canonical(redactions))
```

的前 32 位，其中 `key_fingerprint = sha256("dicom-anon-key-fingerprint:v1|" + ANON_SECRET)`。
指纹是不可逆摘要：数据库、审计与 ZIP 内 `manifest.json` 只保存它，**绝不保存明文密钥**。

下面用 `docker compose` 在同一持久化卷上完整演练一次轮换（数值均为下文
`secret-A` / `secret-B` 实跑所得，可原样复现）。

**1）用密钥 A 启动并提交作业**

```bash
ANON_SECRET=secret-A docker compose up --build -d
curl -s -X POST http://localhost:8000/jobs \
  -F "file=@sample_input.zip" \
  -F "policy=<examples/policy.json" \
  -F "redactions=<examples/redactions.json"
```

```json
{
  "job_id": "880da8b99b3ccf9b7acb0bacd2dca15b",
  "status": "queued",
  "status_url": "/jobs/880da8b99b3ccf9b7acb0bacd2dca15b",
  "detail": null,
  "key_fingerprint": "57d8598384c89f4e875db3c5bf62e4df1e83a27d5bb56fc8242eb8b212e2b9e5"
}
```

同密钥原样重提，返回 **200 + 同一 `job_id`**（仍复用）：

```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:8000/jobs \
  -F "file=@sample_input.zip" -F "policy=<examples/policy.json" \
  -F "redactions=<examples/redactions.json"
# 200
```

**2）换成密钥 B，在同一数据卷上重启，原样重提**

```bash
ANON_SECRET=secret-B docker compose up -d   # 复用命名卷 dicom-anon-data
curl -s -w "\nHTTP %{http_code}\n" -X POST http://localhost:8000/jobs \
  -F "file=@sample_input.zip" -F "policy=<examples/policy.json" \
  -F "redactions=<examples/redactions.json"
```

B 不会命中 A 的旧记录，返回 **202 + 独立新作业 `JOB_B`**：

```json
{"job_id":"c96a46feee1e99f43d8a196f492314c1","status":"queued",
 "status_url":"/jobs/c96a46feee1e99f43d8a196f492314c1","detail":null,
 "key_fingerprint":"a176471f323641812a69c9cdb3e25923cecc2bcd1e9a9e7171574311dc33d91e"}
HTTP 202
```

**3）验证：B 产出独立审计与哈希，A 的旧作业仍可查询/下载**

```bash
# B 的状态：独立指纹、独立 ZIP 哈希、独立 UID 映射
curl -s http://localhost:8000/jobs/c96a46feee1e99f43d8a196f492314c1
#   status=done  key_fingerprint=a176471f…33d91e
#   audit.output.zip_sha256 = 2c5f6f5f16833b3b1df43f4e90fcc89071986aa2b7d08fad00b35b734252585b
#   Study UID = 2.25.41357652652960139871614046357511393935   （A 为 2.25.1613…23381，不同）

# 同密钥 B 再提一次仍复用（200 + JOB_B）
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:8000/jobs \
  -F "file=@sample_input.zip" -F "policy=<examples/policy.json" \
  -F "redactions=<examples/redactions.json"
# 200

# A 的旧 ID 仍可查询，结果原样保留（不会被当成 B 的结果）
curl -s http://localhost:8000/jobs/880da8b99b3ccf9b7acb0bacd2dca15b
#   status=done  key_fingerprint=57d85983…2b9e5
#   result.sha256 = dbb74e23e65a0e50c1ee9aabc50d54acae10ced2179d068b74a2f3820f2810f9

curl -s -o /tmp/a.zip http://localhost:8000/jobs/880da8b99b3ccf9b7acb0bacd2dca15b/download
curl -s -o /tmp/b.zip http://localhost:8000/jobs/c96a46feee1e99f43d8a196f492314c1/download
sha256sum /tmp/a.zip /tmp/b.zip
# dbb74e23…2810f9  /tmp/a.zip   与 JOB_A 的 result.sha256 一致
# 2c5f6f5f…52585b  /tmp/b.zip   与 JOB_B 的 result.sha256 一致；两者互不相同
unzip -p /tmp/a.zip manifest.json | grep -o '"key_fingerprint": "[^"]*"'  # 57d85983… (A)
unzip -p /tmp/b.zip manifest.json | grep -o '"key_fingerprint": "[^"]*"'  # a176471f… (B)
```

**升级自旧版本（无指纹记录）的行为**：旧版数据库在启动时自动迁移，新增
`key_fingerprint` 列；旧作业该列为 `null`、沿用旧 32 位 ID，仍可正常查询和
下载；由于新版作业 ID 带有 `v2` 密钥作用域，任何新提交都不可能命中这些旧行，
因此旧密钥产物永远不会被误返给新密钥的请求。

## 匿名化策略（版本化）

```json
{
  "version": "1.0",
  "salt": "demo-research-project",
  "remove_private_tags": true,
  "strict_references": true,
  "date_shift": { "enabled": true, "max_days": 365 },
  "tags": {
    "keep":    ["PatientSex", "PatientAge", "StudyDescription"],
    "empty":   ["InstitutionName"],
    "remove":  ["PatientAddress", "RequestAttributesSequence"],
    "hash":    ["PatientID"],
    "replace": { "ReferringPhysicianName": "ANON^MD" }
  }
}
```

- `version`：必填，当前支持 `"1.0"`；不支持的版本报 `POLICY_INVALID`。
- `salt`：可选项目级盐，并入策略哈希，隔离不同项目的映射结果。
- `remove_private_tags`（默认 `true`）：删除全部奇数组号私有标签（含序列内）。
- `strict_references`（默认 `true`）：实例引用的 SOPInstanceUID 必须都在
  提交包内，否则报 `MISSING_REFERENCE`（检查发生在动作执行前，因此即使引用
  位于随后会被移除的序列内也仍会被检查）。
- `date_shift.max_days`：日期偏移上限（0–3650 天），偏移量由
  HMAC(患者键) 确定性派生，同一患者所有实例一致。
- `tags`：在默认档案之上叠加。`keep` 将标签从默认清除动作中豁免；
  `empty`/`remove`/`hash`/`replace` 追加或覆盖默认动作。**所有动作都递归
  作用于顶层及保留下来的每一层 SQ 项数据集**，按标签出现次数逐项执行并计入
  审计；`remove` 一个 SQ 标签会整条删除该序列且不再遍历/计数其子项，
  `empty` 一个 SQ 标签则保留一个空序列（项全部丢弃）；对 SQ 标签使用
  `hash`/`replace` 报 `POLICY_CONFLICT`。
- 同一标签被赋予两个动作、`replace` 值违反标签 VR、或试图修改
  受管标签（`StudyInstanceUID`、`PixelData`、行列像素描述符等）
  均报 `POLICY_CONFLICT`。

默认档案：37 个 PHI 标签置空（姓名、生日、机构、医师、入组号、
检查/序列描述、核实人姓名/机构等），`PatientID` 哈希（HMAC-SHA256 前 16 位
十六进制），`PatientSex/Age/Size/Weight` 默认保留。完整清单见 `GET /policies`。

## 像素遮挡框

```json
[
  { "scope": "series", "uid": "1.2.826.0.1.3680043.9.7433.1.1.1",
    "boxes": [[0, 0, 128, 30]], "fill": 0 }
]
```

- `scope`：`instance`（SOPInstanceUID）/ `series` / `study`。
- `boxes`：`[x, y, width, height]` 像素坐标（原点左上），多帧图像逐帧应用。
- `fill`：填充值 0–65535，默认 0（黑）。
- 越界（`REDACTION_OUT_OF_BOUNDS`）、目标不存在
  （`REDACTION_TARGET_NOT_FOUND`）、布局不支持
  （`UNSUPPORTED_PIXEL_LAYOUT`）都会使作业整体失败。

## 错误代码

| 代码 | 含义 |
| --- | --- |
| `ZIP_INVALID` | 非法/损坏的 ZIP 或条目 |
| `READ_ERROR` | 文件形似 DICOM 但无法解析 |
| `NOT_DICOM`（警告） | 非 DICOM 文件被跳过并记入 `warnings` |
| `MISSING_UID` | 缺少 SOP/Study/Series Instance UID 或 SOP Class UID |
| `DUPLICATE_INSTANCE` | 同一 SOPInstanceUID 出现多次 |
| `MISSING_REFERENCE` | 引用的 SOPInstanceUID 不在提交包内 |
| `INVALID_VR` / `INVALID_VALUE` | 未知 VR 或 DA/TM/DT/UI 值非法（附标签号；递归检查 SQ 项内元素） |
| `COMPRESSED_PIXELS` | JPEG/RLE/Deflated 等压缩传输语法（需先解压） |
| `UNSUPPORTED_TRANSFER_SYNTAX` | 非隐式/显式 VR Little Endian（如 Big Endian） |
| `UNSUPPORTED_PIXEL_LAYOUT` | 遮挡目标像素布局不支持 |
| `REDACTION_*` | 遮挡目标缺失 / 遮挡框越界 |
| `POLICY_INVALID` / `POLICY_CONFLICT` | 策略结构非法 / 策略冲突 |
| `NO_INSTANCES` | 包内无可用 DICOM 实例 |

## 确定性说明

输出字节由以下因素唯一决定：输入 ZIP 字节、策略（规范化 JSON）、
遮挡规则、服务密钥 `ANON_SECRET`。具体措施：UID 映射 / 日期偏移 /
值哈希均用 HMAC-SHA256 派生；输出统一编码为 Explicit VR Little Endian、
固定文件元与 128 字节零前导；ZIP 条目按 `STUDY_xxxx/SERIES_xxxx/
INSTANCE_xxxxx.dcm` 确定性命名、固定 1980-01-01 时间戳与压缩级别；
`manifest.json` 键序固定，内含输入/策略哈希与密钥指纹。同一密钥下重复处理
同一输入将得到逐字节相同的结果；轮换 `ANON_SECRET` 后指纹改变，作业判重
重新开作用域，输出也随之不同（见上文「密钥轮换演练」）。

## 安全与合规提示

- 本服务面向研究数据去标识化场景；输出是否满足具体法规（如 HIPAA
  Safe Harbor、GDPR）需由数据负责人评估， burned-in 文本建议配合遮挡框。
- `ANON_SECRET` 决定映射可复现性，请妥善保管并仅在受信环境部署。轮换密钥
  会让后续提交产出独立作业与结果；服务只持久化其 SHA-256 指纹，不留明文。
- UID 映射表（审计中返回）本身属于敏感关联信息，请按研究数据治理要求保存。
