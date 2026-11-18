"""REST API (northbound interface) and dashboard, served by Ryu's WSGI server.

Spec: SDS_Phase2_Design.md section 10.4.
  GET  /aegis/hosts                  all hosts: zone, role, score, tier, override
  GET  /aegis/hosts/{name}           one host + its last 20 ledger events
  GET  /aegis/events?since=SEQ       ledger stream (dashboard)
  GET  /aegis/policy                 current rules
  POST /aegis/policy/reload          hot-reload policy.yaml (purges ALLOW/DENY flows)
  POST /aegis/hosts/{name}/override  body {"tier": "QUARANTINED"} or {"tier": null}
  GET  /aegis/stats                  packet-ins, decisions, decision latency, CPU, memory, flows
  GET  /aegis/mode                   current mode
  GET  /aegis/dashboard              live web dashboard
"""
import json
import os

from ryu.app.wsgi import ControllerBase, Response, route

from models import Tier

DASHBOARD = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dashboard", "index.html")
NAME = {"name": r"[A-Za-z0-9_\-]+"}


def _json(obj, status=200):
    r = Response(content_type="application/json", charset="utf-8",
                 body=json.dumps(obj).encode("utf-8"), status=status)
    r.headers["Access-Control-Allow-Origin"] = "*"
    return r


class AegisRestController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super().__init__(req, link, data, **config)
        self.app = data["aegis_app"]

    @route("aegis", "/aegis/hosts", methods=["GET"])
    def hosts(self, req, **_):
        return _json(self.app.api_hosts())

    @route("aegis", "/aegis/hosts/{name}", methods=["GET"], requirements=NAME)
    def host(self, req, name, **_):
        h = next((x for x in self.app.api_hosts() if x["name"] == name), None)
        if h is None:
            return _json({"error": "unknown host"}, 404)
        h["events"] = [e for e in self.app.trust.events_since(0) if e["host"] == name][-20:]
        return _json(h)

    @route("aegis", "/aegis/hosts/{name}/override", methods=["POST"], requirements=NAME)
    def override(self, req, name, **_):
        if name not in self.app.inventory.hosts:
            return _json({"error": "unknown host"}, 404)
        try:
            body = json.loads(req.body or b"{}")
            tier = body.get("tier")
            tier = Tier[tier] if tier else None
        except (ValueError, KeyError):
            return _json({"error": "body must be {\"tier\": \"QUARANTINED|RESTRICTED|NORMAL|TRUSTED\"|null}"}, 400)
        change = self.app.override(name, tier)
        return _json({"host": name, "override": tier.name if tier is not None else None,
                      "tier": self.app.tier_of(name).name, "changed": change is not None})

    @route("aegis", "/aegis/events", methods=["GET"])
    def events(self, req, **_):
        try:
            since = int(req.params.get("since", 0))
        except ValueError:
            since = 0
        return _json(self.app.trust.events_since(since)[-300:])

    @route("aegis", "/aegis/policy", methods=["GET"])
    def policy(self, req, **_):
        return _json(self.app.policy.describe())

    @route("aegis", "/aegis/policy/reload", methods=["POST"])
    def reload(self, req, **_):
        try:
            self.app.reload_policy()
        except Exception as e:  # report bad YAML instead of crashing
            return _json({"error": str(e)}, 400)
        return _json({"reloaded": True, "rules": len(self.app.policy.rules)})

    @route("aegis", "/aegis/stats", methods=["GET"])
    def stats(self, req, **_):
        return _json(self.app.api_stats())

    @route("aegis", "/aegis/mode", methods=["GET"])
    def mode(self, req, **_):
        return _json({"mode": self.app.mode})

    @route("aegis", "/aegis/dashboard", methods=["GET"])
    def dashboard(self, req, **_):
        with open(DASHBOARD, "rb") as f:
            return Response(content_type="text/html", charset="utf-8", body=f.read())
