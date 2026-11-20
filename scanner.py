import socket
import ssl
import subprocess
import xml.etree.ElementTree as ET
from typing import Dict, List


# ============================================================
# VECTORSCAN - Network Security Scanner
# Nmap-based network security assessment engine
#
# Safe/authorized assessment only.
# This module performs discovery and configuration/exposure checks.
# It does NOT exploit vulnerabilities or confirm CVEs by version alone.
# ============================================================


# Common ports used by the fallback checks and architecture inference.
COMMON_PORTS = [
    21, 22, 23, 25, 53,
    80, 110, 111, 135, 139, 143,
    443, 445, 512, 513, 514,
    1099, 1524, 2049, 2121,
    3306, 3632, 5432,
    5900, 6000, 6667,
    7070, 8000, 8080,
]


SEVERITY_WEIGHT = {
    "critical": 10,
    "high": 7,
    "medium": 4,
    "low": 2,
    "info": 0,
}


# ============================================================
# Risk helpers
# ============================================================

def risk_level(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    if score > 0:
        return "low"
    return "minimal"


def calculate_risk(findings: List[Dict]) -> int:
    """
    Calculate a simple explainable risk score.

    This is a project-level risk model, not an official CVSS score.
    """
    score = 0

    for finding in findings:
        severity = str(
            finding.get("severity", "info")
        ).lower()

        score += SEVERITY_WEIGHT.get(severity, 0)

    return min(score, 100)


# ============================================================
# Basic TCP port check
# ============================================================

def check_port(
    target: str,
    port: int,
    timeout: float = 0.8
) -> bool:
    """
    Fallback TCP connectivity check.

    Returns True when a TCP connection succeeds.
    """
    try:
        with socket.create_connection(
            (target, port),
            timeout=timeout
        ):
            return True

    except (socket.timeout, socket.error, OSError):
        return False


# ============================================================
# HTTP security checks
# ============================================================

def check_http(
    target: str,
    port: int
) -> List[Dict]:
    """
    Perform lightweight HTTP security-header and banner checks.

    Uses Python standard library only.
    """
    findings: List[Dict] = []

    sock = None

    try:
        sock = socket.create_connection(
            (target, port),
            timeout=3
        )

        request = (
            "HEAD / HTTP/1.0\r\n"
            f"Host: {target}\r\n"
            "Connection: close\r\n\r\n"
        )

        sock.sendall(
            request.encode(
                "ascii",
                errors="ignore"
            )
        )

        data = b""

        while True:
            chunk = sock.recv(4096)

            if not chunk:
                break

            data += chunk

            if len(data) >= 16384:
                break

        response = data.decode(
            "iso-8859-1",
            errors="ignore"
        )

        headers: Dict[str, str] = {}

        for line in response.split("\r\n"):
            if ":" in line:
                name, value = line.split(":", 1)

                headers[name.strip().lower()] = value.strip()

        security_headers = [
            "x-frame-options",
            "x-content-type-options",
            "content-security-policy",
            "referrer-policy",
        ]

        missing_headers = [
            header
            for header in security_headers
            if header not in headers
        ]

        if missing_headers:
            findings.append({
                "id": f"http-missing-headers-{port}",
                "title": "Missing HTTP security headers",
                "severity": "low",
                "port": port,
                "service": "http",
                "description": (
                    "The HTTP service does not expose one or more "
                    "common browser security headers."
                ),
                "evidence": ", ".join(
                    missing_headers
                ),
                "recommendation": (
                    "Configure appropriate security headers such as "
                    "X-Frame-Options, X-Content-Type-Options, "
                    "Content-Security-Policy and Referrer-Policy."
                ),
            })

        server_header = headers.get("server")

        if server_header:
            findings.append({
                "id": f"http-server-banner-{port}",
                "title": "Web server banner exposed",
                "severity": "info",
                "port": port,
                "service": "http",
                "description": (
                    "The HTTP response exposes a Server header."
                ),
                "evidence": server_header,
                "recommendation": (
                    "Minimize unnecessary server and version "
                    "information exposed to unauthenticated clients."
                ),
            })

        if port == 80:
            findings.append({
                "id": "unencrypted-http",
                "title": "Unencrypted HTTP service exposed",
                "severity": "medium",
                "port": port,
                "service": "http",
                "description": (
                    "HTTP traffic is exposed without transport "
                    "encryption."
                ),
                "evidence": f"TCP/{port} is serving HTTP.",
                "recommendation": (
                    "Prefer HTTPS and redirect HTTP traffic to TLS."
                ),
            })

    except (socket.timeout, socket.error, OSError):
        pass

    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    return findings


# ============================================================
# TLS checks
# ============================================================

def check_tls(
    target: str,
    port: int = 443
) -> List[Dict]:
    """
    Check the TLS version negotiated by the HTTPS service.

    Note:
    Modern Python/OpenSSL configurations may refuse obsolete
    TLS versions before a connection is established. Therefore,
    absence of this finding does not prove that every old TLS
    version is disabled.
    """
    findings: List[Dict] = []

    try:
        context = ssl.create_default_context()

        with socket.create_connection(
            (target, port),
            timeout=5
        ) as raw_socket:

            with context.wrap_socket(
                raw_socket,
                server_hostname=target
            ) as tls_socket:

                version = tls_socket.version()

                if version in ("TLSv1", "TLSv1.1"):
                    findings.append({
                        "id": f"legacy-tls-{port}",
                        "title": "Legacy TLS protocol detected",
                        "severity": "medium",
                        "port": port,
                        "service": "https",
                        "description": (
                            "The service negotiated an older TLS "
                            "protocol version."
                        ),
                        "evidence": version,
                        "recommendation": (
                            "Disable obsolete TLS versions and "
                            "prefer TLS 1.2 or newer."
                        ),
                    })

    except Exception:
        pass

    return findings


# ============================================================
# Service exposure checks
# ============================================================

def check_service_exposure(
    service: str,
    port: int
) -> List[Dict]:
    """
    Identify commonly exposed services that deserve security review.
    """
    findings: List[Dict] = []

    service_name = (
        service or ""
    ).lower()

    if port == 23 or "telnet" in service_name:
        findings.append({
            "id": f"telnet-{port}",
            "title": "Telnet service exposed",
            "severity": "high",
            "port": port,
            "service": service_name or "telnet",
            "description": (
                "Telnet provides remote access without modern "
                "encrypted transport."
            ),
            "evidence": f"TCP/{port}",
            "recommendation": (
                "Disable Telnet and use SSH or another secure "
                "remote administration protocol."
            ),
        })

    elif port == 21 or "ftp" in service_name:
        findings.append({
            "id": f"ftp-{port}",
            "title": "FTP service exposed",
            "severity": "medium",
            "port": port,
            "service": service_name or "ftp",
            "description": (
                "FTP may transmit credentials and data without "
                "transport encryption."
            ),
            "evidence": f"TCP/{port}",
            "recommendation": (
                "Prefer SFTP/FTPS and disable unnecessary FTP access."
            ),
        })

    elif (
        port == 445
        or "microsoft-ds" in service_name
        or "smb" in service_name
    ):
        findings.append({
            "id": f"smb-{port}",
            "title": "SMB service exposed",
            "severity": "medium",
            "port": port,
            "service": service_name or "smb",
            "description": (
                "SMB is exposed over the network and should be "
                "restricted to trusted hosts."
            ),
            "evidence": f"TCP/{port}",
            "recommendation": (
                "Restrict SMB using firewall rules, disable "
                "unnecessary SMB versions and apply security updates."
            ),
        })

    elif port in (512, 513, 514):
        findings.append({
            "id": f"legacy-remote-{port}",
            "title": "Legacy remote administration service exposed",
            "severity": "high",
            "port": port,
            "service": service_name or "legacy-remote",
            "description": (
                "A legacy remote administration service is exposed."
            ),
            "evidence": f"TCP/{port}",
            "recommendation": (
                "Disable legacy remote administration protocols "
                "and use secure alternatives."
            ),
        })

    elif port == 5900 or "vnc" in service_name:
        findings.append({
            "id": f"vnc-{port}",
            "title": "VNC service exposed",
            "severity": "medium",
            "port": port,
            "service": service_name or "vnc",
            "description": (
                "A remote desktop service is network accessible."
            ),
            "evidence": f"TCP/{port}",
            "recommendation": (
                "Restrict VNC access and use VPN or another "
                "authenticated secure remote-access mechanism."
            ),
        })

    elif port in (3306, 5432, 1433, 1521):
        findings.append({
            "id": f"database-{port}",
            "title": "Database service exposed",
            "severity": "medium",
            "port": port,
            "service": service_name or "database",
            "description": (
                "A database service is directly reachable over "
                "the network."
            ),
            "evidence": f"TCP/{port}",
            "recommendation": (
                "Restrict database access to trusted application "
                "hosts and use authentication and encryption."
            ),
        })

    return findings


# ============================================================
# Service/version assessment
# ============================================================

def check_version_risk(
    service: Dict
) -> List[Dict]:
    """
    Perform conservative assessment using Nmap's service/product data.

    IMPORTANT:
    This does not confirm CVEs. A product/version string alone is
    insufficient to claim a vulnerability is exploitable.
    """
    findings: List[Dict] = []

    port = service.get("port")

    name = (
        service.get("name")
        or ""
    ).lower()

    product = (
        service.get("product")
        or ""
    ).strip()

    version = (
        service.get("version")
        or ""
    ).strip()

    extrainfo = (
        service.get("extrainfo")
        or ""
    ).strip()

    # FTP version/configuration review
    if port == 21 or "ftp" in name:
        findings.append({
            "id": f"ftp-version-assessment-{port}",
            "title": "FTP service requires security review",
            "severity": "medium",
            "port": port,
            "service": product or name or "ftp",
            "description": (
                "FTP is network accessible. Depending on the server "
                "configuration, credentials and data may be exposed "
                "without transport encryption."
            ),
            "evidence": {
                "product": product,
                "version": version,
                "extra": extrainfo,
            },
            "recommendation": (
                "Verify whether FTP is required. Prefer SFTP or FTPS, "
                "disable anonymous access, restrict source networks, "
                "and keep the FTP server updated."
            ),
        })

    # SMB version/configuration review
    if (
        port == 445
        or "microsoft-ds" in name
        or "smb" in name
    ):
        findings.append({
            "id": f"smb-version-assessment-{port}",
            "title": "SMB service requires security review",
            "severity": "medium",
            "port": port,
            "service": product or name or "smb",
            "description": (
                "SMB is exposed over the network. Security impact "
                "depends on SMB version, authentication configuration, "
                "patch level and network exposure."
            ),
            "evidence": {
                "product": product,
                "version": version,
                "extra": extrainfo,
            },
            "recommendation": (
                "Restrict SMB access to trusted hosts, disable obsolete "
                "SMB protocols, require appropriate authentication, "
                "and apply current security updates."
            ),
        })

    # SSH exposure review
    if port == 22 or "ssh" in name:
        findings.append({
            "id": f"ssh-exposure-{port}",
            "title": "SSH service exposed",
            "severity": "low",
            "port": port,
            "service": product or name or "ssh",
            "description": (
                "SSH provides remote administration and is reachable "
                "over the network."
            ),
            "evidence": {
                "product": product,
                "version": version,
            },
            "recommendation": (
                "Restrict SSH access to trusted networks, disable "
                "password authentication where appropriate, use "
                "key-based authentication, and keep OpenSSH updated."
            ),
        })

    # Web server technology disclosure
    if (
        port in (80, 443, 7070, 8000, 8080)
        and product
    ):
        findings.append({
            "id": f"web-version-exposure-{port}",
            "title": "Web server technology identified",
            "severity": "info",
            "port": port,
            "service": product,
            "description": (
                "Nmap identified web server technology and/or "
                "version information."
            ),
            "evidence": {
                "product": product,
                "version": version,
            },
            "recommendation": (
                "Keep the web server and application framework updated "
                "and minimize unnecessary version disclosure."
            ),
        })

    # Database exposure review
    if port in (3306, 5432, 1433, 1521):
        findings.append({
            "id": f"database-version-assessment-{port}",
            "title": "Database service exposed",
            "severity": "medium",
            "port": port,
            "service": product or name or "database",
            "description": (
                "A database service is directly reachable over the "
                "network. Direct database exposure increases attack "
                "surface and should be reviewed."
            ),
            "evidence": {
                "product": product,
                "version": version,
            },
            "recommendation": (
                "Restrict database access to trusted application "
                "servers, enforce strong authentication, use encryption "
                "where appropriate, and apply security updates."
            ),
        })

    return findings


# ============================================================
# Nmap scanner
# ============================================================

def empty_nmap_result(
    error: str
) -> Dict:
    """Return a consistent Nmap failure structure."""
    return {
        "success": False,
        "error": error,
        "services": [],
        "open_ports": [],
        "closed_ports": [],
        "filtered_ports": [],
        "os_matches": [],
        "addresses": [],
        "hostnames": [],
    }


def run_nmap(
    target: str
) -> Dict:
    """
    Run Nmap and parse XML output.

    Current scan profile:
    - Service/version detection
    - OS detection
    - Top 200 TCP ports
    - XML output
    - 120 second timeout

    For a faster demo, top-200 is intentional.
    A future "Full Scan" profile can use -p-.
    """

    command = [
        "nmap",
        "-sV",
        "-O",
        "--osscan-guess",
        "-T4",
        "--top-ports",
        "200",
        "-oX",
        "-",
        target,
    ]

    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120,
            shell=False,
        )

    except FileNotFoundError:
        return empty_nmap_result(
            "Nmap is not installed or is not available in PATH."
        )

    except subprocess.TimeoutExpired:
        return empty_nmap_result(
            "Nmap scan timed out after 120 seconds."
        )

    except Exception as exc:
        return empty_nmap_result(
            f"Nmap execution failed: {exc}"
        )

    stdout = process.stdout or ""
    stderr = process.stderr or ""

    if not stdout.strip():
        return empty_nmap_result(
            stderr.strip()
            or "Nmap returned no XML output."
        )

    try:
        root = ET.fromstring(stdout)

    except ET.ParseError as exc:
        return empty_nmap_result(
            f"Unable to parse Nmap XML: {exc}"
        )

    result = {
        "success": process.returncode == 0,
        "return_code": process.returncode,
        "stderr": stderr.strip(),
        "host_state": "unknown",
        "addresses": [],
        "hostnames": [],
        "os_matches": [],
        "services": [],
        "open_ports": [],
        "closed_ports": [],
        "filtered_ports": [],
    }

    host = root.find("host")

    if host is None:
        return result

    # --------------------------------------------------------
    # Host state
    # --------------------------------------------------------

    status = host.find("status")

    if status is not None:
        result["host_state"] = status.attrib.get(
            "state",
            "unknown"
        )

    # --------------------------------------------------------
    # Addresses
    # --------------------------------------------------------

    for address in host.findall("address"):
        addr = address.attrib.get("addr")

        if addr:
            result["addresses"].append({
                "address": addr,
                "type": address.attrib.get(
                    "addrtype",
                    "unknown"
                ),
            })

    # --------------------------------------------------------
    # Hostnames
    # --------------------------------------------------------

    hostnames_node = host.find("hostnames")

    if hostnames_node is not None:
        for hostname in hostnames_node.findall("hostname"):
            name = hostname.attrib.get("name")

            if name:
                result["hostnames"].append(name)

    # --------------------------------------------------------
    # Ports and services
    # --------------------------------------------------------

    ports_node = host.find("ports")

    if ports_node is not None:
        for port_node in ports_node.findall("port"):
            protocol = port_node.attrib.get(
                "protocol",
                "tcp"
            )

            port_id = port_node.attrib.get("portid")

            try:
                port_number = int(port_id)
            except (TypeError, ValueError):
                continue

            state_node = port_node.find("state")

            state = "unknown"

            if state_node is not None:
                state = state_node.attrib.get(
                    "state",
                    "unknown"
                )

            service_node = port_node.find("service")

            service_data = {
                "port": port_number,
                "protocol": protocol,
                "state": state,
                "name": "",
                "product": "",
                "version": "",
                "extrainfo": "",
                "tunnel": "",
            }

            if service_node is not None:
                service_data["name"] = service_node.attrib.get(
                    "name",
                    ""
                )

                service_data["product"] = service_node.attrib.get(
                    "product",
                    ""
                )

                service_data["version"] = service_node.attrib.get(
                    "version",
                    ""
                )

                service_data["extrainfo"] = service_node.attrib.get(
                    "extrainfo",
                    ""
                )

                service_data["tunnel"] = service_node.attrib.get(
                    "tunnel",
                    ""
                )

            result["services"].append(service_data)

            if state == "open":
                result["open_ports"].append(port_number)

            elif state == "closed":
                result["closed_ports"].append(port_number)

            elif state == "filtered":
                result["filtered_ports"].append(port_number)

    # --------------------------------------------------------
    # OS detection
    # --------------------------------------------------------

    os_node = host.find("os")

    if os_node is not None:
        for match in os_node.findall("osmatch"):
            name = match.attrib.get(
                "name",
                "Unknown"
            )

            accuracy = match.attrib.get(
                "accuracy",
                "0"
            )

            result["os_matches"].append({
                "name": name,
                "accuracy": accuracy,
            })

    return result


# ============================================================
# Firewall / filtering heuristic
# ============================================================

def detect_firewall(
    open_ports: List[int],
    filtered_ports: List[int],
    host_state: str
) -> Dict:
    """
    Infer possible packet filtering from Nmap port states.

    This does NOT identify a specific firewall vendor/product.
    """

    open_count = len(open_ports)
    filtered_count = len(filtered_ports)

    if host_state != "up":
        return {
            "detected": False,
            "confidence": "none",
            "reason": "Host was not confirmed as up.",
        }

    if filtered_count >= 20 and open_count <= 5:
        return {
            "detected": True,
            "confidence": "medium",
            "reason": (
                "Many ports are filtered while only a small "
                "number of ports are exposed."
            ),
        }

    if filtered_count > 0:
        return {
            "detected": True,
            "confidence": "low",
            "reason": (
                "At least one scanned port is filtered, which "
                "may indicate packet filtering."
            ),
        }

    return {
        "detected": False,
        "confidence": "none",
        "reason": "No strong filtering pattern was observed.",
    }


# ============================================================
# Architecture inference
# ============================================================

def build_architecture(
    target: str,
    nmap_result: Dict
) -> Dict:
    """
    Infer possible host roles from network-visible services.

    This is an exposure map, not a full internal asset/process inventory.
    """

    services = nmap_result.get(
        "services",
        []
    )

    roles: List[str] = []
    detected_services: List[Dict] = []

    for service in services:
        if service.get("state") != "open":
            continue

        port = service.get("port")

        name = (
            service.get("name")
            or service.get("product")
            or "unknown"
        )

        detected_services.append({
            "port": port,
            "service": name,
            "product": service.get(
                "product",
                ""
            ),
            "version": service.get(
                "version",
                ""
            ),
        })

        service_lower = name.lower()

        if port in (80, 443, 7070, 8000, 8080):
            if "Web Server" not in roles:
                roles.append("Web Server")

        if port in (22, 23, 3389, 512, 513, 514, 5900):
            if "Remote Administration" not in roles:
                roles.append("Remote Administration")

        if port in (3306, 5432, 1433, 1521):
            if "Database" not in roles:
                roles.append("Database")

        if port in (139, 445, 2049):
            if "File Sharing" not in roles:
                roles.append("File Sharing")

        if port == 53:
            if "DNS" not in roles:
                roles.append("DNS")

        if port in (25, 110, 143):
            if "Mail Service" not in roles:
                roles.append("Mail Service")

        if any(
            keyword in service_lower
            for keyword in (
                "http",
                "apache",
                "nginx",
                "iis",
            )
        ):
            if "Web Server" not in roles:
                roles.append("Web Server")

    return {
        "target": target,
        "exposed_roles": roles,
        "detected_services": detected_services,
        "architecture_note": (
            "Architecture is inferred from network-visible "
            "services and ports. It is not a full internal "
            "process or asset inventory."
        ),
    }


# ============================================================
# Finding de-duplication
# ============================================================

def deduplicate_findings(
    findings: List[Dict]
) -> List[Dict]:
    """
    Prevent duplicate findings when multiple checks identify
    the same condition.
    """

    unique: List[Dict] = []
    seen = set()

    for finding in findings:
        finding_id = finding.get("id")

        if not finding_id:
            unique.append(finding)
            continue

        if finding_id in seen:
            continue

        seen.add(finding_id)
        unique.append(finding)

    return unique


# ============================================================
# Main scan function
# ============================================================

def scan_target(
    target: str
) -> Dict:
    """
    Execute a complete VECTORSCAN assessment.
    """

    nmap_result = run_nmap(target)

    if not nmap_result.get("success"):
        return {
            "target": target,
            "status": "failed",
            "risk_score": 0,
            "risk_level": "minimal",
            "summary": {},
            "findings": [],
            "services": [],
            "open_ports": [],
            "closed_ports": [],
            "filtered_ports": [],
            "os_matches": [],
            "addresses": [],
            "hostnames": [],
            "firewall": {
                "detected": False,
                "confidence": "none",
            },
            "architecture": {},
            "error": nmap_result.get(
                "error",
                "Nmap scan failed."
            ),
        }

    findings: List[Dict] = []

    # --------------------------------------------------------
    # Host information
    # --------------------------------------------------------

    if nmap_result.get("host_state") == "up":
        findings.append({
            "id": "live-host",
            "title": "Live host detected",
            "severity": "info",
            "description": (
                "The target responded to Nmap host discovery."
            ),
            "evidence": nmap_result.get(
                "addresses",
                []
            ),
            "recommendation": (
                "Continue with authorized service and "
                "configuration assessment."
            ),
        })

    # --------------------------------------------------------
    # OS information
    # --------------------------------------------------------

    os_matches = nmap_result.get(
        "os_matches",
        []
    )

    if os_matches:
        best_os = os_matches[0]

        findings.append({
            "id": "os-detected",
            "title": "Operating system fingerprint detected",
            "severity": "info",
            "description": (
                "Nmap identified a probable operating system."
            ),
            "evidence": best_os,
            "recommendation": (
                "Verify the operating system and ensure it "
                "receives current security updates."
            ),
        })

    # --------------------------------------------------------
    # Service exposure + version assessment
    # --------------------------------------------------------

    for service in nmap_result.get(
        "services",
        []
    ):
        if service.get("state") != "open":
            continue

        port = service.get("port")
        name = service.get(
            "name",
            ""
        )

        # Existing exposure checks
        findings.extend(
            check_service_exposure(
                name,
                port
            )
        )

        # Product/version assessment
        findings.extend(
            check_version_risk(
                service
            )
        )

        # HTTP checks
        if port in (
            80,
            8080,
            8000,
            7070
        ):
            findings.extend(
                check_http(
                    target,
                    port
                )
            )

        # HTTPS/TLS checks
        if port == 443:
            findings.extend(
                check_tls(
                    target,
                    port
                )
            )

    # --------------------------------------------------------
    # Firewall detection
    # --------------------------------------------------------

    firewall = detect_firewall(
        nmap_result.get(
            "open_ports",
            []
        ),
        nmap_result.get(
            "filtered_ports",
            []
        ),
        nmap_result.get(
            "host_state",
            "unknown"
        ),
    )

    if firewall.get("detected"):
        findings.append({
            "id": "possible-firewall-filtering",
            "title": "Possible network filtering detected",
            "severity": "info",
            "description": (
                "Port-state patterns suggest that network "
                "filtering may be present."
            ),
            "evidence": firewall,
            "recommendation": (
                "Validate firewall policy and confirm that "
                "only required services are reachable."
            ),
        })

    # --------------------------------------------------------
    # De-duplicate findings
    # --------------------------------------------------------

    findings = deduplicate_findings(
        findings
    )

    # --------------------------------------------------------
    # Risk calculation
    # --------------------------------------------------------

    score = calculate_risk(
        findings
    )

    level = risk_level(
        score
    )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    summary = {
        "total_findings": len(findings),
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "open_ports": len(
            nmap_result.get(
                "open_ports",
                []
            )
        ),
        "closed_ports": len(
            nmap_result.get(
                "closed_ports",
                []
            )
        ),
        "filtered_ports": len(
            nmap_result.get(
                "filtered_ports",
                []
            )
        ),
        "services": len([
            service
            for service in nmap_result.get(
                "services",
                []
            )
            if service.get("state") == "open"
        ]),
    }

    for finding in findings:
        severity = str(
            finding.get(
                "severity",
                "info"
            )
        ).lower()

        if severity in summary:
            summary[severity] += 1

    # --------------------------------------------------------
    # Risk graph
    # --------------------------------------------------------

    risk_graph = {
        "labels": [
            "Critical",
            "High",
            "Medium",
            "Low",
        ],
        "values": [
            summary["critical"],
            summary["high"],
            summary["medium"],
            summary["low"],
        ],
    }

    # --------------------------------------------------------
    # Architecture
    # --------------------------------------------------------

    architecture = build_architecture(
        target,
        nmap_result
    )

    # --------------------------------------------------------
    # Final result
    # --------------------------------------------------------

    return {
        "target": target,
        "status": "completed",
        "risk_score": score,
        "risk_level": level,

        "summary": summary,

        "findings": findings,

        "services": nmap_result.get(
            "services",
            []
        ),

        "open_ports": nmap_result.get(
            "open_ports",
            []
        ),

        "closed_ports": nmap_result.get(
            "closed_ports",
            []
        ),

        "filtered_ports": nmap_result.get(
            "filtered_ports",
            []
        ),

        "os_matches": os_matches,

        "addresses": nmap_result.get(
            "addresses",
            []
        ),

        "hostnames": nmap_result.get(
            "hostnames",
            []
        ),

        "firewall": firewall,

        "architecture": architecture,

        "risk_graph": risk_graph,

        "nmap": {
            "success": nmap_result.get(
                "success",
                False
            ),
            "return_code": nmap_result.get(
                "return_code"
            ),
            "stderr": nmap_result.get(
                "stderr",
                ""
            ),
        },
    }
