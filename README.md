# mime-sanitizer

离线 MIME 附件净化库：处理已投递邮件的原始字节，仅按本地 SHA-256 黑名单
替换恶意附件。不做 URL 检测、邮件收发或持久化。

## 用法

```python
from mime_sanitizer import inspect, neutralize

# {路径: 解码后负载的 SHA-256}
hashes = inspect(raw_bytes)

# 命中黑名单的附件被替换为 7bit text/plain 占位 part（"Attachment removed"）
clean, replaced_paths = neutralize(raw_bytes, blocked_hashes)
```

- 路径为子节点序号元组，根为 `()`；multipart 子节点从 0 编号，
  `message/rfc822` 封装的完整邮件是其第 0 个子节点。
- 附件指 `Content-Disposition: attachment|inline` 的非容器叶子；
  `message/rfc822` 始终作为容器递归检查。
- 无命中时输出与输入逐字节相同；同一黑名单重复净化逐字节不变且报告为空。

## 测试

```sh
python3 -m unittest discover -s tests -v
```
