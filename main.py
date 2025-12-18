"""
Cloud Run / Buildpacks 友好入口：
- 让默认 Python 构建流程能稳定找到 ASGI app（main:app）
- 实际应用逻辑仍在 api/index.py
"""

from api.index import app  # noqa: F401


