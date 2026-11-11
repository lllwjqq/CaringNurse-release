"""预警实时推送 WebSocket（规格附录 A.4：token 鉴权）。"""

import json

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect
from jose import JWTError, jwt
from sqlalchemy import select

from app.config import settings
from app.database import AsyncSessionLocal
from app.models import Patient
from app.services.redis_client import redis_client

router = APIRouter(tags=["WebSocket"])


def _read_claims(token: str) -> int | None:
    """解析 access token，返回用户标识；无效时返回 None。"""
    try:
        claims = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        if claims.get("type") != "access":
            return None
        return int(claims["sub"])
    except (JWTError, ValueError, KeyError):
        return None


async def _authorize_patient(patient_id: int, token: str | None) -> bool:
    """校验 access token，并确认该 patient 属于 token 对应的用户。"""
    if not token:
        return False
    user_id = _read_claims(token)
    if user_id is None:
        return False
    async with AsyncSessionLocal() as session:
        row = (
            await session.execute(select(Patient).where(Patient.user_id == user_id))
        ).scalar_one_or_none()
    return row is not None and row.id == patient_id


@router.websocket("/ws/alerts/{patient_id}")
async def alert_websocket(
    websocket: WebSocket,
    patient_id: int,
    token: str | None = Query(default=None),
):
    await websocket.accept()
    if not await _authorize_patient(patient_id, token):
        # 鉴权失败：accept 后以 4401 关闭，前端据此停止重连
        await websocket.close(code=4401)
        return

    listener = redis_client.client.pubsub()
    topic = "alerts:%d" % patient_id
    await listener.subscribe(topic)
    try:
        while True:
            event = await listener.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if event and event["type"] == "message":
                await websocket.send_text(event["data"])
            try:
                incoming = await websocket.receive_text()
                if incoming == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
            except WebSocketDisconnect:
                break
            except Exception:
                pass
    finally:
        await listener.unsubscribe(topic)
        await listener.close()
