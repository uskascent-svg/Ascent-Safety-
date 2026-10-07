from sqlalchemy import create_engine

from alembic import context
from app.core.config import get_settings
from app.models import Base

target_metadata = Base.metadata
url = get_settings().database_url

if context.is_offline_mode():
    context.configure(url=url, target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()
else:
    with create_engine(url).connect() as conn:
        context.configure(connection=conn, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()
