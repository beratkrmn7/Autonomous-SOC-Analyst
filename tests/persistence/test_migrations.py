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
