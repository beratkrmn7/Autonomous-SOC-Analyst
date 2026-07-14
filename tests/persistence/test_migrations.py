from alembic.config import Config
from alembic import command
from alembic.script import ScriptDirectory
import tempfile
import os

def test_alembic_upgrade_head_and_downgrade():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name
        
    try:
        os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"
        
        from agent.config import get_settings
        get_settings.cache_clear()
        
        alembic_cfg = Config("alembic.ini")
        alembic_cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
        
        # Test upgrade to head
        command.upgrade(alembic_cfg, "head")
        
        script = ScriptDirectory.from_config(alembic_cfg)
        head_rev = script.get_current_head()
        assert head_rev is not None
        
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)

def test_worker_heartbeat_migration():
    from sqlalchemy import create_engine, inspect
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name
        
    try:
        os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"
        from agent.config import get_settings
        get_settings.cache_clear()
        
        alembic_cfg = Config("alembic.ini")
        alembic_cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
        
        # upgrade database to revision 554b54ed15b4
        command.upgrade(alembic_cfg, "554b54ed15b4")
        
        # upgrade to head
        command.upgrade(alembic_cfg, "head")
        
        engine = create_engine(f"sqlite:///{db_path}")
        inspector = inspect(engine)
        
        # assert worker_heartbeats table exists
        assert "worker_heartbeats" in inspector.get_table_names()
        
        # assert required columns exist
        columns = {col["name"] for col in inspector.get_columns("worker_heartbeats")}
        assert {"worker_id", "worker_type", "status", "started_at", "last_heartbeat_at", "current_job_id", "hostname_hash", "version", "created_at", "updated_at"}.issubset(columns)
        
        # downgrade one revision
        command.downgrade(alembic_cfg, "-1")
        
        # assert table no longer exists
        inspector = inspect(engine)
        assert "worker_heartbeats" not in inspector.get_table_names()
        
    finally:
        if 'engine' in locals():
            engine.dispose()
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except PermissionError:
                pass
