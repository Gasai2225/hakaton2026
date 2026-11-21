"""Cursors and node editing locks belong to live project tabs."""
import asyncio
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from time import monotonic, time
from typing import Annotated
from uuid import uuid4

from fastapi import HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import Field

from garden.accounts import SESSION_COOKIE, User, digest
from garden.models import Id, Model, Workflow


ClientId = Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
Coordinate = Annotated[float, Field(strict=True, ge=-1e7, le=1e7, allow_inf_nan=False)]
HEARTBEAT_SECONDS = 8
LEASE_SECONDS = 35
NODE_IDLE_SECONDS = 180


class Point(Model):
    x: Coordinate
    y: Coordinate


class CursorUpdate(Model):
    client_id: ClientId
    cursor: Point | None


class EditLock(Model):
    client_id: ClientId
    node_id: Id | None
    previous_lease_id: ClientId | None = None
    return_lease: bool = False


class EditActivity(Model):
    client_id: ClientId
    node_id: Id
    lease_id: ClientId


@dataclass
class NodeLease:
    node_id: str
    lease_id: str = field(default_factory=lambda: uuid4().hex)
    deadline: float = field(init=False)
    expires_at: int = field(init=False)

    def __post_init__(self):
        self.renew()

    def renew(self):
        self.deadline = monotonic() + NODE_IDLE_SECONDS
        self.expires_at = int((time() + NODE_IDLE_SECONDS) * 1000)


@dataclass
class Tab:
    user: User
    cursor: Point | None = None
    moved: float = 0
    seen: float = field(default_factory=lambda: monotonic())
    lock: NodeLease | None = None

    @property
    def node_id(self) -> str | None:
        return self.lock.node_id if self.lock else None


class Room:
    def __init__(self):
        self.tabs: dict[tuple[bytes, str], Tab] = {}
        self.changed = asyncio.Event()

    def notify(self):
        self.changed.set()
        self.changed = asyncio.Event()

    def discard(self, keys):
        for key in keys:
            del self.tabs[key]
        if keys:
            self.notify()

    def expire(self):
        now = monotonic()
        self.discard([key for key, tab in self.tabs.items() if now - tab.seen >= LEASE_SECONDS])
        for tab in self.tabs.values():
            if tab.lock and tab.lock.deadline <= now:
                tab.lock = None
                self.notify()

    def next_wakeup(self, keepalive: float) -> float:
        deadline = keepalive
        for tab in self.tabs.values():
            if tab.lock:
                deadline = min(deadline, tab.lock.deadline)
        return deadline

    def locks(self, viewer_key):
        return [{"node_id": tab.lock.node_id, "user_id": tab.user.id, "name": tab.user.name, "mine": key == viewer_key,
                 "lease_id": tab.lock.lease_id, "expires_at": tab.lock.expires_at}
                for key, tab in self.tabs.items() if tab.lock]

    def peers(self, viewer: str) -> list[dict]:
        # One person may have several visible windows. Prefer their last moving cursor.
        users: dict[str, Tab] = {}
        for tab in self.tabs.values():
            if tab.user.id == viewer:
                continue
            previous = users.get(tab.user.id)
            if previous is None or (tab.cursor and (not previous.cursor or tab.moved > previous.moved)):
                users[tab.user.id] = tab
        return [{"id": t.user.id, "name": t.user.name, "cursor": t.cursor.model_dump() if t.cursor else None}
                for t in sorted(users.values(), key=lambda t: (t.user.name, t.user.id))]


def rooms(request: Request) -> dict[str, Room]:
    if not hasattr(request.app.state, "board_rooms"):
        request.app.state.board_rooms = {}
    return request.app.state.board_rooms


def tab_key(request: Request, client_id: str) -> tuple[bytes, str]:
    return digest(request.cookies[SESSION_COOKIE]), client_id


def open_stream(request: Request, project_id: str, client_id: str, user: User, authorize: Callable):
    key = tab_key(request, client_id)

    async def events():
        registry = rooms(request)
        room = registry.setdefault(project_id, Room())
        tab = room.tabs[key] = Tab(user)
        room.notify()
        previous = None
        keepalive = monotonic() + HEARTBEAT_SECONDS
        try:
            while room.tabs.get(key) is tab:
                try:
                    authorize()
                except HTTPException:
                    break
                now = monotonic()
                room.expire()
                if room.tabs.get(key) is not tab:
                    break
                changed = room.changed
                snapshot = {"peers": room.peers(user.id), "locks": room.locks(key)}
                if snapshot != previous:
                    event = {**snapshot, "server_time": int(time() * 1000)}
                    yield "data: " + json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n\n"
                    previous = snapshot
                    keepalive = monotonic() + HEARTBEAT_SECONDS
                elif now >= keepalive:
                    yield ": keep-alive\n\n"
                    keepalive = monotonic() + HEARTBEAT_SECONDS
                try:
                    deadline = room.next_wakeup(keepalive)
                    await asyncio.wait_for(changed.wait(), timeout=max(0, deadline - monotonic()))
                except TimeoutError:
                    pass
        finally:
            if room.tabs.get(key) is tab:
                room.discard([key])
            if not room.tabs and registry.get(project_id) is room:
                del registry[project_id]

    return StreamingResponse(events(), media_type="text/event-stream",
                             headers={"Cache-Control": "private, no-store", "X-Accel-Buffering": "no"})


def active_tab(request: Request, project_id: str, client_id: str, status: int = 409) -> tuple[Room, Tab]:
    room = rooms(request).get(project_id)
    if room:
        room.expire()
        tab = room.tabs.get(tab_key(request, client_id))
        if tab:
            return room, tab
    raise HTTPException(status, "Связь с доской прервалась. Подключитесь к проекту ещё раз.")


def move_cursor(request: Request, project_id: str, body: CursorUpdate):
    room, tab = active_tab(request, project_id, body.client_id)
    tab.seen = monotonic()
    if tab.cursor != body.cursor:
        tab.cursor, tab.moved = body.cursor, tab.seen
        room.notify()


def locked(tab: Tab) -> HTTPException:
    return HTTPException(423, f"Блок «{tab.node_id}» сейчас редактирует {tab.user.name}.")


def require_lease(tab: Tab | None, lease_id: str) -> NodeLease:
    if not tab or not tab.lock or tab.lock.lease_id != lease_id:
        raise HTTPException(423, "Редактирование блока завершено. Выберите его снова.")
    return tab.lock


def edit_node(request: Request, project_id: str, body: EditLock) -> str | None:
    room, current = active_tab(request, project_id, body.client_id)
    if body.previous_lease_id is not None:
        require_lease(current, body.previous_lease_id)
    elif "previous_lease_id" in body.model_fields_set and current.lock:
        raise HTTPException(423, "В этой вкладке уже редактируется блок.")
    if body.node_id is not None:
        for tab in room.tabs.values():
            if tab is not current and tab.node_id == body.node_id:
                raise locked(tab)
    current.seen = monotonic()
    if current.node_id != body.node_id:
        current.lock = NodeLease(body.node_id) if body.node_id is not None else None
        room.notify()
    return current.lock.lease_id if current.lock else None


def edit_activity(request: Request, project_id: str, body: EditActivity):
    room, tab = active_tab(request, project_id, body.client_id, status=423)
    lease = require_lease(tab, body.lease_id)
    if lease.node_id != body.node_id:
        raise HTTPException(423, "Этот блок не выбран для редактирования.")
    tab.seen = monotonic()
    lease.renew()
    room.notify()


def check_write(request: Request, project_id: str, client_id: str | None, before: Workflow, after: Workflow,
                lease_id: str | None = None) -> NodeLease | None:
    if client_id:
        room, writer = active_tab(request, project_id, client_id, status=423)
    else:
        room, writer = rooms(request).get(project_id), None
        if room:
            room.expire()
    if lease_id is not None and before != after:
        require_lease(writer, lease_id)
    if not room:
        return
    foreign = {tab.node_id: tab for tab in room.tabs.values() if tab is not writer and tab.node_id is not None}
    if not writer and not foreign:
        return
    old_nodes, new_nodes = ({node.id: node for node in graph.nodes} for graph in (before, after))
    edited_lease = None
    for ident, node in old_nodes.items():
        if node == new_nodes.get(ident):
            continue
        if ident in foreign:
            raise locked(foreign[ident])
        if writer and writer.node_id != ident:
            raise HTTPException(423, f"Чтобы изменить блок «{ident}», снова начните его редактирование.")
        if writer:
            edited_lease = writer.lock
    old_edges, new_edges = ({edge.id: edge for edge in graph.edges} for graph in (before, after))
    for ident in old_edges.keys() | new_edges.keys():
        old, new = old_edges.get(ident), new_edges.get(ident)
        if old == new:
            continue
        for edge in (old, new):
            if edge:
                holder = foreign.get(edge.source) or foreign.get(edge.target)
                if holder:
                    raise locked(holder)
                if writer and writer.node_id in (edge.source, edge.target):
                    edited_lease = writer.lock
    return edited_lease


def after_write(request: Request, project_id: str, graph: Workflow, edited_lease: NodeLease | None):
    room = rooms(request).get(project_id)
    if room:
        remaining = {node.id for node in graph.nodes}
        if edited_lease and edited_lease.node_id in remaining:
            edited_lease.renew()
            room.notify()
        for tab in room.tabs.values():
            if tab.node_id is not None and tab.node_id not in remaining:
                tab.lock = None
                room.notify()


def remove_account(request: Request, project_id: str, user_id: str):
    room = rooms(request).get(project_id)
    if room:
        room.discard([k for k, tab in room.tabs.items() if tab.user.id == user_id])
