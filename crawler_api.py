# crawler_api.py
import os
import threading
from datetime import datetime, timedelta
from typing import Optional, Dict, List

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from bson import ObjectId

# Async client for read APIs & index creation
from motor.motor_asyncio import AsyncIOMotorClient
# Sync client for background thread writes
from pymongo import MongoClient, ASCENDING
from pymongo.errors import DuplicateKeyError

from core.engine import DiscoveryEngine
from core.engine_playwright import PlaywrightDiscoveryEngine

app = FastAPI(title="Crawler API")

# ----- Mongo config -----
# compose passes: mongodb service hostname; include db name in URI
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/webscanner")

_async_client = AsyncIOMotorClient(MONGO_URI)
_async_db = _async_client.get_database()

# in-memory live logs
live_logs: Dict[str, List[str]] = {}
stop_flags: Dict[str, bool] = {}
scan_threads: Dict[str, threading.Thread] = {}

class ScanRequest(BaseModel):
    target_url: str
    depth: int = 2
    threads: int = 10
    login_url: Optional[str] = None
    login_data: Optional[str] = None
    use_headless: bool = False          # << NEW: opt-in JS-aware crawler
    concurrency: int = 5                # used by headless engine
    sample_http_logs: bool = True       # store limited http_logs (TTL’d)
    http_log_ttl_days: int = 7

def _log(scan_id: str, msg: str):
    live_logs.setdefault(scan_id, []).append(msg)

@app.on_event("startup")
async def _ensure_indexes():
    # scans
    await _async_db.scans.create_index("started_at")
    await _async_db.scans.create_index("phase")
    # urls
    await _async_db.urls.create_index([("scan_id", ASCENDING), ("url", ASCENDING)], unique=True, name="uniq_scan_url")
    await _async_db.urls.create_index([("scan_id", ASCENDING), ("status", ASCENDING), ("depth", ASCENDING)])
    await _async_db.urls.create_index("discovered_at")
    # http_logs (set TTL on expire_at)
    await _async_db.http_logs.create_index("timestamp")
    await _async_db.http_logs.create_index([("scan_id", ASCENDING), ("url", ASCENDING)])
    await _async_db.http_logs.create_index("expire_at", expireAfterSeconds=0)
    # scan_events (TTL)
    await _async_db.scan_events.create_index("ts")
    await _async_db.scan_events.create_index("expire_at", expireAfterSeconds=0)

def _write_scan_event(db, scan_id, msg, kind="crawler", level="info", ttl_days=7):
    db.scan_events.insert_one({
        "scan_id": scan_id,
        "kind": kind,
        "level": level,
        "msg": msg,
        "ts": datetime.utcnow(),
        "expire_at": datetime.utcnow() + timedelta(days=ttl_days)
    })

def _run_scan_in_thread(scan_id: str, params: ScanRequest):
    """
    Runs either classic DiscoveryEngine or PlaywrightDiscoveryEngine,
    and writes outputs to MongoDB (sync PyMongo) to avoid thread event-loop issues.
    """
    sync_client = MongoClient(MONGO_URI)
    db = sync_client.get_database()

    try:
        # create scan header
        db.scans.insert_one({
            "_id": scan_id,
            "target": params.target_url,
            "scope": {"depth": params.depth},
            "auth": {"used": bool(params.login_url), "login_url": params.login_url or None},
            "started_at": datetime.utcnow(),
            "finished_at": None,
            "phase": "running",
            "stats": {"urls_discovered": 0, "urls_queued_for_attack": 0, "urls_attacked": 0, "findings_total": 0},
            "tech_stack": []
        })
        _write_scan_event(db, scan_id, f"Scan started for {params.target_url}")

        # choose engine
        if params.use_headless:
            _log(scan_id, "[INFO] Using headless (Playwright) crawler")
            engine = PlaywrightDiscoveryEngine(
                base_url=params.target_url,
                max_depth=params.depth,
                concurrency=params.concurrency,
                login_url=params.login_url,
                login_data=params.login_data
            )
        else:
            _log(scan_id, "[INFO] Using classic (requests+BS4) crawler")
            engine = DiscoveryEngine(
                base_url=params.target_url,
                max_depth=params.depth,
                num_threads=params.threads,
                login_url=params.login_url,
                login_data=params.login_data
            )

        # run discovery
        report_text = engine.run_discovery()
        _log(scan_id, f"[INFO] {report_text}")

        # write discovered urls
        inserted = 0
        for fp, state in engine.discovered_states.items():
            doc = {
                "scan_id": scan_id,
                "url": state["url"],
                "method": "GET",
                "parent": state.get("parent"),
                "depth": state.get("depth", 0),
                "content_hash": state.get("content_hash"),
                "status": "pending",  # queue for Attack Engine
                "discovered_at": datetime.utcnow(),
                "tech_stack": list(engine.tech_profile) if getattr(engine, "tech_profile", None) else [],
                "input_vectors": state.get("input_vectors"),
                "request_template": state.get("request_template"),
                "last_error": None
            }
            try:
                db.urls.insert_one(doc)
                inserted += 1
                _write_scan_event(db, scan_id, f"Discovered URL: {doc['url']}")
            except DuplicateKeyError:
                pass

        # sampled http logs (headless only)
        if params.sample_http_logs and getattr(engine, "sample_logs", None):
            expire_at = datetime.utcnow() + timedelta(days=params.http_log_ttl_days)
            batch = []
            for it in engine.sample_logs[:2000]:  # cap to avoid explosion
                batch.append({
                    "scan_id": scan_id,
                    "url": it["url"],
                    "request": {"method": it["method"], "headers": {}},  # keep headers minimal
                    "response": {"status": it.get("status")},
                    "kind": it.get("kind"),
                    "timestamp": datetime.utcnow(),
                    "expire_at": expire_at
                })
            if batch:
                db.http_logs.insert_many(batch)

        # finalize scan header
        db.scans.update_one(
            {"_id": scan_id},
            {"$set": {
                "finished_at": datetime.utcnow(),
                "phase": "completed",
                "stats.urls_discovered": len(engine.discovered_states),
                "stats.urls_queued_for_attack": inserted,
                "tech_stack": list(engine.tech_profile) if getattr(engine, "tech_profile", None) else []
            }}
        )
        _write_scan_event(db, scan_id, f"Scan finished. Unique states: {len(engine.discovered_states)}, URLs queued: {inserted}")

        _log(scan_id, f"[INFO] Scan finished. Unique states: {len(engine.discovered_states)}, URLs saved: {inserted}")

    except Exception as e:
        _log(scan_id, f"[ERROR] {e}")
        db.scans.update_one({"_id": scan_id}, {"$set": {"phase": "failed", "finished_at": datetime.utcnow()}})
        _write_scan_event(db, scan_id, f"Scan failed: {e}", level="error")


@app.post("/api/scan/start")
async def start_scan(request: ScanRequest):
    scan_id = str(ObjectId())
    live_logs[scan_id] = [f"[INFO] Scan scheduled for {request.target_url}"]
    stop_flags[scan_id] = False
    t = threading.Thread(target=_run_scan_in_thread, args=(scan_id, request), daemon=True)
    t.start()
    scan_threads[scan_id] = t
    return {"scan_id": scan_id, "status": "running"}

@app.post("/api/scan/stop/{scan_id}")
async def stop_scan(scan_id: str):
    if scan_id not in live_logs:
        raise HTTPException(status_code=404, detail="Unknown scan_id")
    stop_flags[scan_id] = True  # (engine is not checking this yet; future improvement)
    _log(scan_id, "[INFO] Stop requested (not yet cooperative).")
    return {"scan_id": scan_id, "status": "stop_requested"}

@app.get("/api/scan/logs/{scan_id}")
async def get_logs(scan_id: str):
    return {"logs": live_logs.get(scan_id, [])}

@app.get("/api/scan/urls/{scan_id}")
async def get_urls(scan_id: str):
    urls = await _async_db.urls.find({"scan_id": scan_id}).to_list(5000)
    for u in urls:
        u["_id"] = str(u["_id"])
    return {"urls": urls}

@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str):
    scan = await _async_db.scans.find_one({"_id": scan_id})
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")
    scan["_id"] = str(scan["_id"])
    return scan

@app.get("/api/scan/events/{scan_id}")
async def get_scan_events(scan_id: str, limit: int = 200):
    cursor = _async_db.scan_events.find({"scan_id": scan_id}).sort("ts", 1).limit(limit)
    events = await cursor.to_list(limit)
    for e in events:
        e["_id"] = str(e["_id"])
    return {"events": events}
