"""集中式日志配置 — 终端(Rich) + 日志文件(Rotating) 双通道输出

使用方式:
    from .log import setup_logging, get_logger

    # 在 CLI 入口（sync 命令）初始化一次
    logger = setup_logging()

    # 在各模块获取子 logger
    logger = get_logger("EcsCollector")
    logger.info("同步完成")
    logger.error("同步失败", exc_info=True)  # 自动记录 traceback
"""

import logging
import logging.handlers
from pathlib import Path

from rich.logging import RichHandler

LOG_DIR = Path("data/logs")
LOG_FILE = LOG_DIR / "sync.log"

# 全局标记：是否已初始化（避免重复添加 handler）
_initialized = False


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    """配置双通道日志系统

    - 终端: RichHandler — 彩色输出、带时间戳、错误自动显示格式化 traceback
    - 日志文件: RotatingFileHandler — 纯文本、带完整时间戳和 traceback、自动轮转

    Args:
        level: 终端最低输出级别（默认 INFO，文件始终记录 DEBUG）

    Returns:
        根 logger 实例
    """
    global _initialized

    root_logger = logging.getLogger("aliyun_inv")

    # 防止重复初始化（CLI 可能多次调用）
    if _initialized:
        return root_logger

    _initialized = True
    root_logger.setLevel(logging.DEBUG)  # 设最低级别为 DEBUG，由各 handler 自己过滤

    # 确保日志目录存在
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    # ─── 终端 Handler ───
    rich_handler = RichHandler(
        show_time=True,
        show_path=False,
        markup=True,
        rich_tracebacks=True,
        tracebacks_show_locals=False,
    )
    rich_handler.setLevel(level)
    # 终端格式：只显示消息内容（RichHandler 自动加时间、级别）
    rich_formatter = logging.Formatter("%(message)s")
    rich_handler.setFormatter(rich_formatter)
    root_logger.addHandler(rich_handler)

    # ─── 日志文件 Handler ───
    file_handler = logging.handlers.RotatingFileHandler(
        LOG_FILE,
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=3,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)  # 文件记录所有级别（包括 DEBUG）
    file_formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler.setFormatter(file_formatter)
    root_logger.addHandler(file_handler)

    return root_logger


def get_logger(name: str = "") -> logging.Logger:
    """获取子 logger

    Args:
        name: 子 logger 名称，如 "EcsCollector"、"sync"

    Returns:
        子 logger 实例（如 "aliyun_inv.EcsCollector"）
    """
    if name:
        return logging.getLogger(f"aliyun_inv.{name}")
    return logging.getLogger("aliyun_inv")


def is_initialized() -> bool:
    """检查日志系统是否已初始化"""
    return _initialized