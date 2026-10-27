"""
Database service for the utils layer.

Thin re-export of the canonical services.db_service module so pipeline
utilities (triage agent, reporting, verification) can reach persistence
without importing from the services package — keeping the layering
one-directional (services may use utils, utils should not depend on
services internals).
"""
from services.db_service import (
    get_db,
    init_db,
    upsert_user,
    save_investigation,
    find_recent_investigation,
    get_investigation_history,
    update_investigation_analyst,
    get_investigation_by_id,
    delete_investigation,
)

__all__ = [
    "get_db",
    "init_db",
    "upsert_user",
    "save_investigation",
    "find_recent_investigation",
    "get_investigation_history",
    "update_investigation_analyst",
    "get_investigation_by_id",
    "delete_investigation",
]
