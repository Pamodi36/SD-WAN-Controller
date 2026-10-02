"""Small SD-WAN controller.

The CPE-facing datastore calls use the RESTCONF JSON shape exposed by Clixon.
"""

from __future__ import annotations
from pathlib import Path
import os

import http.server
import ipaddress
import json
import argparse
import logging
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict

LOGGER = logging.getLogger("sdwan-controller")

def _json_request(method: str, url: str, body: dict | None = None) -> dict:
    data = None if body is None else json.dumps(body).encode()

    request = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Content-Type": "application/yang-data+json",
            "Accept": "application/yang-data+json",
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=2) as response:
            raw = response.read()

    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode(errors="replace")

        LOGGER.error(
            "HTTP %s for %s %s\nResponse body:\n%s",
            exc.code,
            method,
            url,
            error_body,
        )

        raise

    return json.loads(raw) if raw else {}

@dataclass
class CPE:
    id: str
    hostname: str
    management_ip: str
    url: str
    data: dict

class Controller:
    def __init__(self, clixon_port: int = 8383):
        self.clixon_port = clixon_port
        self.cpes: dict[str, CPE] = {}
        self.lock = threading.RLock()

        self.registry_file = Path(__file__).with_name("cpe_registry.json")
        self.registry = self._load_registry()

    def _load_registry(self) -> dict:
        if not self.registry_file.exists():
            LOGGER.info("No persistent CPE registry found; starting empty")
            return {}
    
        try:
            with self.registry_file.open("r", encoding="utf-8") as file:
                registry = json.load(file)
    
            LOGGER.info(
                "Loaded persistent CPE registry with %d entries",
                len(registry),
            )
            return registry
    
        except (OSError, json.JSONDecodeError) as exc:
            LOGGER.error("Failed to load CPE registry: %s", exc)
            return {}
    
    
    def _save_registry(self) -> None:
        temp_file = self.registry_file.with_suffix(".tmp")
    
        with temp_file.open("w", encoding="utf-8") as file:
            json.dump(self.registry, file, indent=2)
    
        os.replace(temp_file, self.registry_file)
    
    
    def _next_cpe_id(self) -> str:
        used_numbers = []
    
        for record in self.registry.values():
            cpe_id = record.get("cpe-id")
    
            if isinstance(cpe_id, str) and cpe_id.startswith("cpe-"):
                try:
                    used_numbers.append(int(cpe_id.removeprefix("cpe-")))
                except ValueError:
                    pass
    
        next_number = max(used_numbers, default=0) + 1
        return f"cpe-{next_number}"

    def _get_or_create_cpe_identity(
        self,
        hostname: str,
        management_ip: str,
    ) -> tuple[str, str]:
    
        existing = self.registry.get(hostname)
    
        if existing:
            cpe_id = existing["cpe-id"]
            lan_prefix = existing["lan-prefix"]
    
            # Management IP may change while identity stays the same.
            if existing.get("management-ip") != management_ip:
                existing["management-ip"] = management_ip
                self._save_registry()
    
            LOGGER.info(
                "Reusing persistent identity: hostname=%s cpe-id=%s lan-prefix=%s",
                hostname,
                cpe_id,
                lan_prefix,
            )
    
            return cpe_id, lan_prefix
    
        cpe_id = self._next_cpe_id()
        lan_prefix = self._lan_prefix(cpe_id)
    
        self.registry[hostname] = {
            "cpe-id": cpe_id,
            "management-ip": management_ip,
            "lan-prefix": lan_prefix,
        }
    
        self._save_registry()
    
        LOGGER.info(
            "Created persistent identity: hostname=%s cpe-id=%s lan-prefix=%s",
            hostname,
            cpe_id,
            lan_prefix,
        )
    
        return cpe_id, lan_prefix

    def _url(self, management_ip: str) -> str:
        return f"http://{management_ip}:{self.clixon_port}/restconf/data/sdwan-cpe:sdwan"

    def _get(self, url: str) -> dict:
        LOGGER.debug("GET %s", url)
        return _json_request("GET", url)

    def _patch(self, url: str, body: dict) -> None:
        LOGGER.debug("PATCH %s", url)
        _json_request("PATCH", url, body)

    def _state_url(self, management_ip: str) -> str:
        return f"{self._url(management_ip)}/state"

    @staticmethod
    def _sdwan(data: dict) -> dict:
        return data.get("sdwan-cpe:sdwan", data.get("sdwan", {}))

    def _wan_address(self, remote: CPE, bind_wan_link: str) -> str | None:
        data = self._get(self._state_url(remote.management_ip))
        state = data.get("sdwan-cpe:state", data.get("state", {}))

        for link in state.get("wan-link-state", []):
            if link.get("name") == bind_wan_link:
                address = link.get("ipv4-address")

                if address:
                    return address

                LOGGER.warning(
                    "No live IPv4 address for %s/%s",
                    remote.id,
                    bind_wan_link,
                )
                return None

        LOGGER.warning(
            "No WAN state for %s/%s",
            remote.id,
            bind_wan_link,
        )
        return None


    @staticmethod
    def _lan_prefix(cpe_id: str) -> str:
        return f"10.0.{int(cpe_id.removeprefix('cpe-'))}.0/24"


    def announce(self, payload: dict) -> None:
        hostname = payload.get("hostname")
        management_ip = payload.get("management-ip")
    
        if not isinstance(hostname, str) or not hostname:
            raise ValueError("hostname is required")
    
        try:
            ipaddress.ip_address(management_ip)
        except (TypeError, ValueError):
            raise ValueError("management-ip must be an IP address") from None
    
        with self.lock:
            LOGGER.info(
                "CPE announcement: hostname=%s management-ip=%s",
                hostname,
                management_ip,
            )
    
            url = self._url(management_ip)
    
            # Confirm that the CPE is reachable.
            data = self._get(url)
    
            # Persistent identity lookup/allocation.
            cpe_id, lan_network_string = self._get_or_create_cpe_identity(
                hostname,
                management_ip,
            )
    
            # Example:
            # 10.0.1.0/24
            lan_network = ipaddress.ip_network(lan_network_string)
    
            # ens7 gets 10.0.1.1/24
            lan_interface_ip = (
                f"{lan_network.network_address + 1}/"
                f"{lan_network.prefixlen}"
            )
    
            # DHCP range:
            # 10.0.1.100 - 10.0.1.200
            pool_start = str(lan_network.network_address + 100)
            pool_end = str(lan_network.network_address + 200)
    
            body = {
                "system": {
                    "local-cpe-id": cpe_id,
                },
                "interfaces": {
                    "lan": {
                        "lan-link": [
                            {
                                "name": "ens7",
                                "admin-enabled": True,
                                "ipv4-prefix": lan_interface_ip,
                                "dhcp-server": {
                                    "enabled": True,
                                    "pool-start": pool_start,
                                    "pool-end": pool_end,
                                    "dns-server": "8.8.8.8",
                                    "lease-time-seconds": 86400,
                                },
                            }
                        ]
                    }
                },
            }
    
            self._patch(
                url,
                {
                    "sdwan-cpe:sdwan": body
                },
            )
    
            # Read back final CPE configuration.
            data = self._get(url)
    
            self.cpes[cpe_id] = CPE(
                cpe_id,
                hostname,
                management_ip,
                url,
                data,
            )
    
            LOGGER.info(
                "Registered %s (%s), LAN=%s",
                cpe_id,
                hostname,
                lan_interface_ip,
            )
    
            self._reconcile()

    def _reconcile(self) -> None:
        # ponytail: pairwise scan; replace with indexed prefix discovery only if CPE count makes it matter.
        for cpe in self.cpes.values():
            cpe.data = self._get(cpe.url)
        if len(self.cpes) < 2:
            return
        LOGGER.info("Reconciling tunnels for %d CPEs", len(self.cpes))
        cpes = list(self.cpes.values())
        for local in cpes:
            local_data = self._sdwan(local.data)
            local_tunnels = local_data.get("overlay", {}).get("tunnel", [])
            for tunnel in local_tunnels:
                remote_id = tunnel.get("remote-cpe-id")
                remote_name = tunnel.get("remote-tunnel-name")
                if not remote_id or not remote_name:
                    LOGGER.warning("Skipping %s/%s: tunnel intent is incomplete", local.id, tunnel.get("name"))
                    continue
                remote = self.cpes.get(remote_id)
                if not remote:
                    LOGGER.info("Skipping %s/%s: intended peer %s is not registered", local.id, tunnel["name"], remote_id)
                    continue
                remote_tunnels = self._sdwan(remote.data).get("overlay", {}).get("tunnel", [])
                remote_tunnel = next((item for item in remote_tunnels if item.get("name") == remote_name), None)
                if not remote_tunnel:
                    LOGGER.warning("Skipping %s/%s: remote tunnel %s/%s was not found", local.id, tunnel["name"], remote_id, remote_name)
                    continue
                bind_wan_link = remote_tunnel.get("bind-wan-link")
                if not bind_wan_link:
                    LOGGER.warning("Skipping %s/%s: remote tunnel has no bind-wan-link", local.id, tunnel["name"])
                    continue
                peer_address = self._wan_address(remote, bind_wan_link)
                if not peer_address or not remote_tunnel.get("local-public-key"):
                    LOGGER.warning("Skipping %s/%s: remote WAN address or public key is missing", local.id, tunnel["name"])
                    continue
                remote_lan_links = self._sdwan(remote.data).get("interfaces", {}).get("lan", {}).get("lan-link", [])
                allowed_prefix = [remote_lan_links[0]["ipv4-prefix"]] if remote_lan_links and remote_lan_links[0].get("ipv4-prefix") else remote_tunnel.get("advertised-prefix", [])
                updated = dict(tunnel)
                updated.pop("local-public-key", None)
                updated["resolved-peer"] = {
                    "peer-address": peer_address,
                    "peer-port": remote_tunnel.get("local-port", 51820),
                    "peer-public-key": remote_tunnel["local-public-key"],
                    "allowed-prefix": allowed_prefix,
                }
                self._patch(local.url, {"sdwan-cpe:sdwan": {"overlay": {"tunnel": [updated]}}})
                LOGGER.info("Configured %s/%s -> %s/%s", local.id, tunnel["name"], remote.id, remote_tunnel["name"])
        for cpe in cpes:
            cpe.data = self._get(cpe.url)

    def snapshot(self) -> list[dict]:
        with self.lock:
            return [asdict(cpe) for cpe in self.cpes.values()]


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/announce":
            self.send_error(404)
            return
        try:
            size = int(self.headers.get("Content-Length", 0))
            self.server.controller.announce(json.loads(self.rfile.read(size)))
        except (ValueError, KeyError, urllib.error.URLError, TimeoutError) as error:
            LOGGER.warning("Announcement failed: %s", error)
            self.send_error(400, str(error))
            return
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        if self.path != "/cpes":
            self.send_error(404)
            return
        body = json.dumps(self.server.controller.snapshot()).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def serve(controller: Controller, host: str = "127.0.0.1", port: int = 9000):
    server = http.server.ThreadingHTTPServer((host, port), _Handler)
    server.controller = controller
    return server


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Dummy SD-WAN controller")
    parser.add_argument("--listen-ip", default="127.0.0.1", help="Controller bind address")
    parser.add_argument("--listen-port", type=int, default=9000, help="Controller HTTP port")
    parser.add_argument("--clixon-port", type=int, default=8001, help="RESTCONF port on each CPE")
    parser.add_argument("--log-level", default="INFO", choices=("DEBUG", "INFO", "WARNING", "ERROR"))
    args = parser.parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    LOGGER.info("Listening on %s:%d; CPE RESTCONF port=%d", args.listen_ip, args.listen_port, args.clixon_port)
    serve(Controller(args.clixon_port), args.listen_ip, args.listen_port).serve_forever()
