#!/usr/bin/env python3
"""
sing-box 配置脱敏脚本
将敏感字段替换为 ***，输出到 stdout 或新文件
用法: python3 sanitize_config.py config.json [output.json]
"""

import json
import sys
import re
from copy import deepcopy

# 需要脱敏的字段名（精确匹配）
SENSITIVE_KEYS = {
    "uuid",
    "password",
    "secret",
    "public_key",
    "private_key",
    "pre_shared_key",
    "short_id",
}

# 需要脱敏的路径字段（文件名保留，路径前缀打码）
PATH_KEYS = {
    "certificate_path",
    "key_path",
}

# 值中包含敏感内容时需要整个值脱敏的字段
VALUE_SENSITIVE_KEYS = {
    "server",
    "server_name",
}


def redact_token_in_url(url):
    """替换 URL 中 token= 后面的值"""
    return re.sub(r"(token=)[^&]+", r"\1**********************", url)


def sanitize_value(value, key="", depth=0):
    """递归脱敏"""
    if isinstance(value, str):
        # URL 中的 token
        if "token=" in value.lower():
            return redact_token_in_url(value)
        # 看起来像 base64 公钥/证书（长随机串）
        if key in VALUE_SENSITIVE_KEYS and len(value) > 10:
            return "**********************"
        return value

    if isinstance(value, list):
        return [sanitize_value(v, key, depth + 1) for v in value]

    if isinstance(value, dict):
        return sanitize_dict(value, depth + 1)

    return value


def sanitize_dict(obj, depth=0):
    result = {}
    for k, v in obj.items():
        if k in SENSITIVE_KEYS:
            result[k] = "**********************"
        elif k in VALUE_SENSITIVE_KEYS and isinstance(v, str) and len(v) > 10:
            # DNS 劫持使用的短域名（如 dns.google）保留，长 SNI/域名打码
            result[k] = "**********************"
        elif k == "certificate" and isinstance(v, list):
            # 证书内容，打码
            if v and "BEGIN CERTIFICATE" in str(v[0]):
                result[k] = ["-----BEGIN CERTIFICATE-----",
                             "**********************",
                             "-----END CERTIFICATE-----"]
            else:
                result[k] = "**********************"
        elif k in PATH_KEYS:
            # 保留文件名，打码路径
            if "/" in v:
                result[k] = "**********************/" + v.rsplit("/", 1)[-1]
            else:
                result[k] = "**********************/" + v
        elif k == "url" and isinstance(v, str):
            result[k] = redact_token_in_url(v)
        elif isinstance(v, dict):
            result[k] = sanitize_dict(v, depth + 1)
        elif isinstance(v, list):
            result[k] = [sanitize_value(item, k, depth + 1) for item in v]
        else:
            result[k] = v
    return result


def main():
    if len(sys.argv) < 2:
        print("用法: python3 sanitize_config.py config.json [output.json]")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else None

    with open(input_path, "r", encoding="utf-8") as f:
        config = json.load(f)

    sanitized = sanitize_dict(config)

    json_out = json.dumps(sanitized, indent=2, ensure_ascii=False)

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(json_out)
        print(f"已输出到 {output_path}")
    else:
        print(json_out)


if __name__ == "__main__":
    main()
