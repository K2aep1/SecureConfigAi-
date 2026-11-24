"""Cursor (keyset) pagination.

Offset pagination gets slower with depth and skips or duplicates rows when new items
arrive between page fetches. These helpers implement an opaque cursor over
``(started_at, id)`` (or ``(created_at, id)``) so a page is a single indexed range scan.
"""

from __future__ import annotations

import base64
import binascii
import uuid
from collections.abc import Callable, Sequence
from datetime import datetime
from typing import Any, Generic, TypeVar

from fastapi import HTTPException, Query, status
from sqlalchemy import and_, or_
from sqlalchemy.orm import Session

T = TypeVar("T")

MAX_LIMIT = 200
DEFAULT_LIMIT = 25


def encode_cursor(timestamp: datetime, row_id: Any) -> str:
    raw = f"{timestamp.isoformat()}|{row_id}"
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii").rstrip("=")


def decode_cursor(cursor: str) -> tuple[datetime, uuid.UUID]:
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
        ts_text, id_text = raw.split("|", 1)
        return datetime.fromisoformat(ts_text), uuid.UUID(id_text)
    except (ValueError, binascii.Error, UnicodeDecodeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid pagination cursor"
        ) from exc


class Page(Generic[T]):
    __slots__ = ("items", "next_cursor", "has_more", "limit")

    def __init__(self, items: Sequence[T], next_cursor: str | None, has_more: bool, limit: int) -> None:
        self.items = list(items)
        self.next_cursor = next_cursor
        self.has_more = has_more
        self.limit = limit

    def as_dict(self, serialize: Callable[[T], dict]) -> dict[str, Any]:
        return {
            "items": [serialize(item) for item in self.items],
            "next_cursor": self.next_cursor,
            "has_more": self.has_more,
            "limit": self.limit,
        }


def page_params(
    limit: int = Query(DEFAULT_LIMIT, ge=1, le=MAX_LIMIT, description="Maximum number of items to return."),
    cursor: str | None = Query(None, description="Opaque cursor from a previous page."),
) -> tuple[int, str | None]:
    return limit, cursor


def apply_keyset(
    session: Session,
    query,
    *,
    order_column,
    id_column,
    limit: int,
    cursor: str | None,
    descending: bool = True,
):
    """Apply the keyset predicate and order, and fetch ``limit + 1`` rows."""
    if cursor:
        ts, row_id = decode_cursor(cursor)
        if descending:
            predicate = or_(
                order_column < ts,
                and_(order_column == ts, id_column < row_id),
            )
        else:
            predicate = or_(
                order_column > ts,
                and_(order_column == ts, id_column > row_id),
            )
        query = query.where(predicate)

    order = (order_column.desc(), id_column.desc()) if descending else (order_column.asc(), id_column.asc())
    rows = list(session.scalars(query.order_by(*order).limit(limit + 1)).all())

    has_more = len(rows) > limit
    items = rows[:limit]
    next_cursor = None
    if has_more and items:
        last = items[-1]
        next_cursor = encode_cursor(getattr(last, order_column.key), getattr(last, id_column.key))
    return Page(items, next_cursor, has_more, limit)
