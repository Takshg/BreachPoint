"""The Granite analyst prompt and output schema (decision D15).

Granite reads ONLY the description text: no CVE ID, dates, scores or vendor history, and it is
never asked whether something was exploited. Every field describes what the text says, so the
model's own background knowledge has as little room as possible to leak later events.

This file has no project imports so it can be copied to Colab as is.
"""
from __future__ import annotations

import json

PROMPT_VERSION = "v3"

CATEGORIES = {
    "edge_network": "VPN, firewall, gateway, router, load balancer, SD-WAN, network appliance",
    "file_transfer": "managed file transfer, file sharing or sync servers",
    "remote_management": "remote access/support, IT or device management, RMM, monitoring, helpdesk, backup servers",
    "web_app": "web application, CMS (not a WordPress plugin), e-commerce, portal, web framework app",
    "wordpress_plugin": "WordPress plugin or theme",
    "collaboration": "email server, chat, office suite server, wiki, document management",
    "enterprise_app": "ERP, CRM, HR, ITSM, business suites",
    "dev_tool": "CI/CD, source control, build servers, developer platforms, AI/ML serving tools",
    "browser": "web browser or browser engine",
    "os_kernel": "operating system, kernel, drivers, firmware of PCs or servers",
    "mobile": "phone or tablet OS or app",
    "desktop_app": "desktop software, media players, PDF readers, office desktop apps",
    "library": "software library, SDK, package or framework used inside other software",
    "database": "database or data store",
    "virtualization_cloud": "hypervisor, containers, cloud platform, orchestration",
    "iot_device": "camera, NAS, printer, smart device, consumer router firmware",
    "ics_ot": "industrial control, SCADA, PLC, medical or building systems",
    "security_product": "antivirus, EDR, identity/SSO, password manager, security appliance software",
    "other": "none of the above",
}

ATTACK_TYPES = ["rce", "auth_bypass", "command_injection", "sql_injection", "deserialization",
                "file_read_or_traversal", "file_upload", "ssrf", "privilege_escalation", "xss_or_csrf",
                "denial_of_service", "info_disclosure", "memory_corruption", "other"]

YES_NO = ["yes", "no", "unclear"]

FIELDS = ["vendor", "product", "category", "internet_facing", "pre_auth", "attack_type", "server_product"]

SCHEMA = {
    "type": "object",
    "properties": {
        "vendor": {"type": "string", "maxLength": 60},
        "product": {"type": "string", "maxLength": 80},
        "category": {"type": "string", "enum": list(CATEGORIES)},
        "internet_facing": {"type": "string", "enum": YES_NO},
        "pre_auth": {"type": "string", "enum": YES_NO},
        "attack_type": {"type": "string", "enum": ATTACK_TYPES},
        "server_product": {"type": "string", "enum": YES_NO},
    },
    "required": FIELDS,
    "additionalProperties": False,
}

SYSTEM = f"""You are a vulnerability analyst. Read one vulnerability description and classify the affected software. Use only what the description says plus general knowledge of what kind of product it is. Answer with JSON only, always with all 7 fields.

vendor: the vendor or project, short. "unknown" if not stated.
product: the product, short. "unknown" if not stated.

category: pick by checking these rules in order, and use the first that fits:
1. Plugin or theme for WordPress or WooCommerce, or text mentioning WordPress -> wordpress_plugin
2. "Linux kernel", Windows or macOS components, operating system, driver, firmware of PCs or servers -> os_kernel
3. Phone or tablet OS or app (Android, iOS, Samsung SMR) -> mobile
4. Camera, NAS, printer, smart home device -> iot_device
5. Router, VPN, firewall, gateway, load balancer, network appliance -> edge_network
6. Endpoint or device manager, remote support, RMM, monitoring, helpdesk, IT management (Ivanti EPM, SimpleHelp, WhatsUp Gold) -> remote_management
7. Only if the text names industrial, SCADA, PLC, CNC, medical or building control systems -> ics_ot
8. Otherwise the best match of:
{chr(10).join(f'  - {k}: {v}' for k, v in CATEGORIES.items() if k not in ('wordpress_plugin', 'os_kernel', 'mobile', 'iot_device', 'edge_network', 'remote_management', 'ics_ot'))}
Use "other" only if nothing fits. Use security_product only for products whose purpose is security. A business application is enterprise_app or web_app.

internet_facing: "yes" if this kind of software is usually reachable from the internet (web apps, WordPress sites, VPNs, routers, mail servers, public APIs, file transfer servers); "no" if usually internal or local (desktop and phone apps, kernels, libraries, local tools, industrial systems); otherwise "unclear".

pre_auth: can someone with no account and no help from a user do it?
- "no" if the text mentions any of: authenticated, logged-in, login required, privileges, admin, contributor, subscriber, local attacker, physical access, or a user or victim having to click, open or visit something (including all XSS and CSRF).
- "yes" only if the text says unauthenticated, without authentication, or a remote attacker with none of the conditions above.
- "unclear" if the text does not say.

attack_type: the main result, one of {", ".join(ATTACK_TYPES)}. Use "rce" for arbitrary code execution, "command_injection" for OS commands. Use "other" if none fit.

server_product: "yes" if organisations typically run this on their own servers or appliances; "no" for desktop or phone apps, libraries, browsers, consumer devices and WordPress plugins; otherwise "unclear"."""

_EXAMPLES = [
    ("The Foo Gallery plugin for WordPress is vulnerable to Stored Cross-Site Scripting in all versions up to 2.1 due to insufficient input sanitization. Authenticated attackers with contributor-level access can inject scripts.",
     dict(vendor="unknown", product="Foo Gallery", category="wordpress_plugin", internet_facing="yes", pre_auth="no", attack_type="xss_or_csrf", server_product="no")),
    ("In the Linux kernel, the following vulnerability has been resolved: net: fix use-after-free in foo_rcv when the socket is closed.",
     dict(vendor="Linux", product="Linux kernel", category="os_kernel", internet_facing="no", pre_auth="unclear", attack_type="memory_corruption", server_product="yes")),
    ("Exampleco C20 IP camera firmware before 1.2 allows unauthenticated remote attackers to execute OS commands via the ping parameter.",
     dict(vendor="Exampleco", product="C20 IP camera", category="iot_device", internet_facing="yes", pre_auth="yes", attack_type="command_injection", server_product="no")),
    ("Improper access control in Settings prior to SMR Release 1 allows local attackers to access sensitive data.",
     dict(vendor="unknown", product="Settings", category="mobile", internet_facing="no", pre_auth="no", attack_type="info_disclosure", server_product="no")),
    ("AcmeVPN Gateway before 9.1 contains a stack-based buffer overflow that allows a remote unauthenticated attacker to execute arbitrary code.",
     dict(vendor="Acme", product="AcmeVPN Gateway", category="edge_network", internet_facing="yes", pre_auth="yes", attack_type="rce", server_product="yes")),
    ("SQL injection in the reports module of OrderDesk ERP 5 allows an authenticated attacker to read the database.",
     dict(vendor="unknown", product="OrderDesk ERP", category="enterprise_app", internet_facing="yes", pre_auth="no", attack_type="sql_injection", server_product="yes")),
    ("PDFView 3.2 has an out-of-bounds write when parsing a crafted file, which can lead to code execution if a user opens the file.",
     dict(vendor="unknown", product="PDFView", category="desktop_app", internet_facing="no", pre_auth="no", attack_type="rce", server_product="no")),
    ("Path traversal in Fleetwise Endpoint Manager before 7.4 allows a remote unauthenticated attacker to read sensitive files from the core server.",
     dict(vendor="unknown", product="Fleetwise Endpoint Manager", category="remote_management", internet_facing="yes", pre_auth="yes", attack_type="file_read_or_traversal", server_product="yes")),
    ("Improper access control in Windows Print Spooler allows an authorized attacker to elevate privileges locally.",
     dict(vendor="Microsoft", product="Windows Print Spooler", category="os_kernel", internet_facing="no", pre_auth="no", attack_type="privilege_escalation", server_product="yes")),
]


def messages(description: str) -> list[dict]:
    text = " ".join(str(description).split())[:2000]
    msgs = [{"role": "system", "content": SYSTEM}]
    for d, a in _EXAMPLES:
        msgs += [{"role": "user", "content": f"Description:\n{d}"},
                 {"role": "assistant", "content": json.dumps(a)}]
    return msgs + [{"role": "user", "content": f"Description:\n{text}"}]


def parse(text: str) -> dict | None:
    """Parse and validate one answer; None if it doesn't fit the schema."""
    try:
        start, end = text.index("{"), text.rindex("}") + 1
        d = json.loads(text[start:end])
    except (ValueError, json.JSONDecodeError):
        return None
    if not all(k in d for k in FIELDS):
        return None
    for k, allowed in (("category", CATEGORIES), ("internet_facing", YES_NO), ("pre_auth", YES_NO),
                       ("attack_type", ATTACK_TYPES), ("server_product", YES_NO)):
        if d[k] not in allowed:
            return None
    return {k: str(d[k])[:80] for k in FIELDS}
