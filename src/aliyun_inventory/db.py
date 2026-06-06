"""数据库引擎、会话与初始化"""

from pathlib import Path

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from .models import Base


def get_engine(db_url: str = "sqlite:///data/aliyun_inventory.db") -> "Engine":
    """创建 SQLAlchemy 引擎

    对于 SQLite 相对路径，自动确保目录存在。
    """
    if db_url.startswith("sqlite:///"):
        db_path = db_url.replace("sqlite:///", "")
        # 确保目录存在
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    engine = create_engine(
        db_url,
        echo=False,
        # SQLite 需要这个设置以支持多线程写
        connect_args={"check_same_thread": False},
    )
    return engine


def init_db(engine: "Engine") -> None:
    """创建所有数据库表 + 自动补齐缺失的列"""
    Base.metadata.create_all(engine)
    _add_missing_columns(engine)


def _add_missing_columns(engine: "Engine") -> None:
    """自动 ALTER TABLE ADD COLUMN — 补齐模型中新增但数据库中缺失的列

    SQLite 不支持 ALTER TABLE 的许多操作（如删列、改类型），
    但 ADD COLUMN 是支持的。这里只做「加列」这个最安全的操作。
    """
    inspector = inspect(engine)
    for model_class in Base.registry._class_registry.values():
        if not hasattr(model_class, "__tablename__"):
            continue
        table_name = model_class.__tablename__
        if not inspector.has_table(table_name):
            continue

        existing_columns = {col["name"] for col in inspector.get_columns(table_name)}
        model_columns = {col.name for col in model_class.__table__.columns}

        missing = model_columns - existing_columns
        for col_name in missing:
            col_obj = model_class.__table__.columns[col_name]
            # 构造 ALTER TABLE 语句
            col_type = col_obj.type.compile(dialect=engine.dialect)
            nullable = "" if col_obj.nullable else " NOT NULL"
            default = ""
            if col_obj.default is not None:
                default = f" DEFAULT {col_obj.default.arg}"
            elif col_obj.nullable:
                default = " DEFAULT NULL"

            sql = f"ALTER TABLE {table_name} ADD COLUMN {col_name} {col_type}{nullable}{default}"
            with engine.begin() as conn:
                conn.execute(text(sql))


def get_session(engine: "Engine") -> Session:
    """创建数据库会话"""
    maker = sessionmaker(bind=engine)
    return maker()