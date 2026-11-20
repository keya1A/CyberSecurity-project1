import asyncio
import ipaddress
import socket
import uuid
import shlex
import subprocess
from typing import Dict

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .models import ScanRequest
from .scanner import scan_target


# =========================================================
# FastAPI Application
# =========================================================

app = FastAPI(
    title="VectorScan - Advanced Network Vulnerability Scanner",
    version="1.0.0",
)


# =========================================================
# CORS
# =========================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================================
# In-memory scan storage
# =========================================================

scans: Dict[str, dict] = {}


# =========================================================
# Nmap Request Model
# =========================================================

class NmapRequest(BaseModel):
    command: str
    authorized: bool


# =========================================================
# Root
# =========================================================

@app.get("/")
def root():
    return {
        "status": "VectorScan API running",
        "version": "1.0.0",
    }


# =========================================================
# Health Check
# =========================================================

@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "service": "vector-scan",
    }


# =========================================================
# Target Validation
# =========================================================

def validate_target(target: str) -> str:
    target = target.strip()

    if not target:
        raise HTTPException(
            status_code=400,
            detail="Target is required.",
        )

    # Check IP address
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    # Basic hostname validation
    if len(target) > 253:
        raise HTTPException(
            status_code=400,
            detail="Invalid target.",
        )

    try:
        resolved = socket.gethostbyname(target)
        return resolved

    except socket.gaierror:
        raise HTTPException(
            status_code=400,
            detail="Target cannot be resolved.",
        )


# =========================================================
# NMAP TERMINAL
# =========================================================

@app.post("/api/tools/nmap")
def run_nmap(request: NmapRequest):

    # Authorization check
    if not request.authorized:
        raise HTTPException(
            status_code=403,
            detail="Authorization is required.",
        )

    command = request.command.strip()

    if not command:
        raise HTTPException(
            status_code=400,
            detail="Nmap command is required.",
        )

    # -----------------------------------------
    # Parse command safely
    # -----------------------------------------

    try:
        args = shlex.split(command)

    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid command syntax.",
        )

    if not args:
        raise HTTPException(
            status_code=400,
            detail="Empty command.",
        )

    # First argument must be nmap
    if args[0].lower() != "nmap":
        raise HTTPException(
            status_code=400,
            detail="Only Nmap commands are allowed.",
        )

    # -----------------------------------------
    # Block shell injection / chaining
    # -----------------------------------------

    blocked_tokens = [
        ";",
        "&&",
        "||",
        "|",
        ">",
        "<",
        "`",
        "$(",
        "${",
    ]

    for arg in args:
        for blocked in blocked_tokens:
            if blocked in arg:
                raise HTTPException(
                    status_code=400,
                    detail="Invalid command.",
                )

    # -----------------------------------------
    # Limit dangerous Nmap options
    # -----------------------------------------

    blocked_options = [
        "--script",
        "-e",
        "--proxies",
        "--data",
        "--data-string",
    ]

    for arg in args:
        lower_arg = arg.lower()

        for option in blocked_options:
            if lower_arg.startswith(option):
                raise HTTPException(
                    status_code=400,
                    detail=f"Nmap option '{option}' is not allowed.",
                )

    # -----------------------------------------
    # Execute Nmap
    # -----------------------------------------

    try:

        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=120,
            shell=False,
        )

        output = result.stdout

        if result.stderr:
            output += "\n" + result.stderr

        return {
            "success": result.returncode == 0,
            "command": command,
            "output": output,
            "return_code": result.returncode,
        }

    except FileNotFoundError:

        raise HTTPException(
            status_code=500,
            detail=(
                "Nmap is not installed or is not available in PATH. "
                "Install Nmap and restart the terminal."
            ),
        )

    except subprocess.TimeoutExpired:

        raise HTTPException(
            status_code=408,
            detail="Nmap scan timed out after 120 seconds.",
        )

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=str(error),
        )


# =========================================================
# Background Scan
# =========================================================

async def execute_scan(scan_id: str, target: str):

    scans[scan_id]["status"] = "running"

    try:

        result = await asyncio.to_thread(
            scan_target,
            target,
        )

        scans[scan_id].update(
            {
                "status": "completed",
                **result,
            }
        )

    except Exception as error:

        scans[scan_id].update(
            {
                "status": "failed",
                "error": str(error),
            }
        )


# =========================================================
# CREATE SECURITY SCAN
# =========================================================

@app.post("/api/scans")
async def create_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
):

    # Authorization
    if not request.authorized:
        raise HTTPException(
            status_code=403,
            detail="You must confirm authorization before scanning.",
        )

    # Validate target
    target = validate_target(request.target)

    # Generate scan ID
    scan_id = f"scan_{uuid.uuid4().hex[:12]}"

    # Initial scan object
    scans[scan_id] = {
        "scan_id": scan_id,
        "target": target,
        "status": "queued",
        "risk_score": 0,
        "risk_level": "unknown",
        "summary": {},
        "findings": [],
        "risk_graph": {},
    }

    # Start background scan
    background_tasks.add_task(
        execute_scan,
        scan_id,
        target,
    )

    return {
        "scan_id": scan_id,
        "target": target,
        "status": "queued",
    }


# =========================================================
# SECURITY REPORT
# =========================================================

@app.get("/api/scans/{scan_id}/report")
def get_scan_report(scan_id: str):
    scan = scans.get(scan_id)

    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan not found.",
        )

    if scan.get("status") != "completed":
        raise HTTPException(
            status_code=409,
            detail="Report is available after the scan completes.",
        )

    return {
        "report_title": (
            "VECTORSCAN Network Security Assessment Report"
        ),
        "target": scan.get("target"),
        "risk_score": scan.get("risk_score", 0),
        "risk_level": scan.get("risk_level", "unknown"),
        "executive_summary": {
            "host_state": scan.get("host_state", "unknown"),
            "open_ports": scan.get("open_ports", 0),
            "closed_ports": scan.get("closed_ports", 0),
            "filtered_ports": scan.get("filtered_ports", 0),
            "os": scan.get("os", {}),
            "firewall": scan.get("firewall", {}),
            "services": scan.get("services", []),
        },
        "findings": scan.get("findings", []),
        "architecture": scan.get("architecture", {}),
        "risk_graph": scan.get("risk_graph", {}),
    }


# =========================================================
# GET SCAN RESULT
# =========================================================

@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str):

    scan = scans.get(scan_id)

    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan not found.",
        )

    return scan