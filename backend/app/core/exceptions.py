from fastapi import HTTPException, status


def not_found(entity_name: str, entity_id: str | None = None):
    suffix = f" with id {entity_id}" if entity_id else ""
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"{entity_name}{suffix} not found",
    )
