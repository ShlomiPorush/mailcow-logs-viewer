"""The About page shows which PostgreSQL version the app runs on."""
import re

from app.database import get_db_context
from app.routers.settings import get_settings_info


def test_settings_info_names_the_postgresql_version():
    with get_db_context() as db:
        config = get_settings_info(db=db)['configuration']
    # The bare number, without the distribution build that SHOW server_version adds
    assert re.fullmatch(r'\d+(\.\d+)*', config['database_version'])
