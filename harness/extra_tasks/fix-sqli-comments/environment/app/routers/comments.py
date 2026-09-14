from fastapi import APIRouter, HTTPException
from db import get_pool
from models import Comment, CommentCreate

router = APIRouter(tags=["comments"])


@router.get("/items/{item_id}/comments", response_model=list[Comment])
async def list_comments(item_id: int):
    pool = await get_pool()
    async with pool.acquire() as conn:
        item = await conn.fetchrow("SELECT id FROM items WHERE id = $1", item_id)
        if not item:
            raise HTTPException(status_code=404, detail="Item not found")

        rows = await conn.fetch(
            "SELECT * FROM comments WHERE item_id = $1 ORDER BY created_at ASC", item_id
        )
    return [dict(r) for r in rows]


@router.post("/items/{item_id}/comments", response_model=Comment)
async def create_comment(item_id: int, comment: CommentCreate):
    pool = await get_pool()
    async with pool.acquire() as conn:
        item = await conn.fetchrow("SELECT id FROM items WHERE id = $1", item_id)
        if not item:
            raise HTTPException(status_code=404, detail="Item not found")

        # VULNERABLE: values concatenated into the statement
        query = (
            "INSERT INTO comments (item_id, author_id, body) VALUES ("
            + str(item_id) + ", " + str(comment.author_id) + ", '" + comment.body + "') RETURNING *"
        )
        row = await conn.fetchrow(query)
    return dict(row)
