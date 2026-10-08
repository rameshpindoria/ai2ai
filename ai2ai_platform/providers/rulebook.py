"""Provider B's agent: 'RuleBook', a deterministic, rules-based IT agent (no AI model at all).

It knows nothing about simulator scenarios. It reads the ticket (plain words) and the real state of the customer's
environment through the protocol, finds anomalies with generic health rules, proposes reversible fixes (each one
approved by the customer's human), and escalates anything that needs a security-level change.
It never treats text found inside data as instructions: it only looks at structured fields."""
import re

HEALTHY_HOMEPAGE = "https://www.bing.com"
EXPECTED_LOCAL_ADMINS = {"it-admin"}


class RuleBookAgent:
    name = "RuleBook IT agent"
    poll_interval = 0.1

    def handle(self, ctx):
        self.ctx, self.t = ctx, ctx.ticket.lower()
        self.findings, self.fixed, self.escalations = [], [], []
        users = ctx.read_data("m365.users.list") or []
        self.users = {u["upn"]: u for u in users}
        self.mentioned = [u for u in users if re.search(r"\b" + re.escape(u["name"].split()[0].lower()) + r"\b", self.t)]
        eps = ctx.read_data("endpoints.list") or []
        self.host_of = {e["user"]: e["hostname"] for e in eps}

        handled = self.lifecycle_requests()
        if not handled:
            self.account_checks()
            self.mail_checks()
            self.endpoint_checks()
            self.shared_service_checks()
        if self.escalations:
            self.ctx.escalate(" ".join(self.escalations))
        summary = (f"Fixed: {', '.join(self.fixed) or 'nothing'}. "
                   f"Escalated: {', '.join(self.escalations) or 'nothing'}.")
        self.ctx.complete(summary, self.findings)

    # ----- helpers -----
    def change(self, op, args, label):
        res = self.ctx.request_change(op, args)
        if res.get("ok"):
            self.fixed.append(label)
        else:
            self.findings.append({"severity": "MEDIUM", "text": f"Could not {label}: {res.get('reason')}"})
        return res.get("ok")

    def escalate(self, why):
        self.escalations.append(why)
        self.findings.append({"severity": "HIGH", "text": why})

    def targets(self):
        return self.mentioned or list(self.users.values())

    def hosts(self):
        if self.mentioned:
            return [self.host_of[u["upn"]] for u in self.mentioned if u["upn"] in self.host_of]
        return list(self.host_of.values())

    def topic(self, *words):
        return any(w in self.t for w in words)

    # ----- requests that name a lifecycle action -----
    def lifecycle_requests(self):
        emails = re.findall(r"[a-z0-9.\-]+@[a-z0-9.\-]+\.[a-z]+", self.t)
        new = [e for e in emails if e not in self.users and self.topic("new starter", "joining", "new staff")]
        if new:
            upn = new[0]
            m = re.search(r"new starter,?\s+([A-Z][a-z]+ [A-Z][a-z]+)", self.ctx.ticket)
            name = m.group(1) if m else upn.split("@")[0].title()
            dm = re.search(r"joining the (\w+) team", self.t)
            dept = dm.group(1).title() if dm else "General"
            ok = self.change("m365.user.create", {"upn": upn, "name": name, "department": dept}, f"create {upn}")
            if ok:
                lic = self.ctx.read_data("m365.licences.list") or {}
                sku = next((k for k, v in lic.items() if v["assigned"] < v["purchased"]), None)
                if sku:
                    self.change("m365.licence.assign", {"upn": upn, "sku": sku}, f"assign {sku} to {upn}")
                peers = [u for u in self.users.values() if u["department"].lower() == dept.lower()]
                groups = sorted(set().union(*[set(p["groups"]) for p in peers])) if peers else ["all-staff"]
                for g in groups:
                    self.change("m365.group.add_member", {"group": g, "upn": upn}, f"add {upn} to {g}")
            return True
        if self.mentioned and self.topic("leaves today", "leaving", "leaver", "offboard", "last day"):
            u = self.mentioned[0]
            self.change("m365.user.block_signin", {"upn": u["upn"]}, f"block sign-in for {u['upn']}")
            if self.topic("keep", "mailbox"):
                self.change("m365.mailbox.convert_to_shared", {"upn": u["upn"]}, f"convert {u['upn']} mailbox to shared")
            for sku in u["licences"]:
                self.change("m365.licence.unassign", {"upn": u["upn"], "sku": sku}, f"free {sku} from {u['upn']}")
            return True
        mv = re.search(r"moved (?:into|to) the (\w+) team", self.t)
        if mv and self.mentioned:
            group, u = mv.group(1), self.mentioned[0]
            known = self.ctx.read_data("m365.groups.list") or {}
            if group in known and group not in u["groups"]:
                self.change("m365.group.add_member", {"group": group, "upn": u["upn"]}, f"add {u['upn']} to {group}")
            return True
        return False

    # ----- generic health rules -----
    def account_checks(self):
        if self.topic("approval prompt", "mfa", "authenticator", "new phone"):
            who = ", ".join(u["upn"] for u in self.mentioned) or "the user"
            self.escalate(f"Resetting sign-in verification (MFA) for {who} is a security change; a person must do it.")
            return
        for u in self.targets():
            if u["locked_out"]:
                self.change("m365.user.unlock", {"upn": u["upn"]}, f"unlock {u['upn']}")
            if u["password_expired"]:
                self.escalate(f"{u['upn']}'s password has expired; a password reset is a security change for a person.")

    def mail_checks(self):
        for u in self.targets():
            mb = self.ctx.read_data("m365.mailbox.get", {"upn": u["upn"]}) or {}
            if mb and mb["size_mb"] > 0.9 * mb["quota_mb"] and not mb["archive"]:
                self.change("m365.mailbox.archive.enable", {"upn": u["upn"]}, f"enable archive for {u['upn']}")
            domain = u["upn"].split("@")[1]
            for r in self.ctx.read_data("m365.mailbox.rules.list", {"upn": u["upn"]}) or []:
                if r.get("enabled") and r.get("action") == "forward" and not str(r.get("target", "")).endswith(domain):
                    self.change("m365.mailbox.rule.disable", {"upn": u["upn"], "rule_id": r["id"]},
                                f"disable external forwarding rule {r['id']} on {u['upn']}")
            od = self.ctx.read_data("m365.onedrive.status", {"upn": u["upn"]}) or {}
            if od and od.get("sync") != "ok":
                self.change("m365.onedrive.resync", {"upn": u["upn"]}, f"reset OneDrive sync for {u['upn']}")
        if self.topic("mailbox", "@"):
            for box in self.ctx.read_data("m365.shared_mailboxes.list") or []:
                if box["address"] in self.t:
                    for u in self.mentioned:
                        if u["upn"] not in box["members"]:
                            self.change("m365.shared_mailbox.add_member", {"mailbox": box["address"], "upn": u["upn"]},
                                        f"give {u['upn']} access to {box['address']}")

    def endpoint_checks(self):
        net = None
        printers = None
        for h in self.hosts():
            d = self.ctx.read_data("endpoint.disk", {"host": h}) or {}
            if d and d["disk_free_gb"] < 0.1 * d["disk_total_gb"] and d["temp_gb"] > 0:
                self.change("endpoint.temp.clear", {"host": h}, f"clear temporary files on {h}")
            for a in self.ctx.read_data("endpoint.startup_apps", {"host": h}) or []:
                if a["enabled"] and a["impact"] == "high" and not a["essential"]:
                    self.change("endpoint.startup_app.disable", {"host": h, "app": a["name"]},
                                f"stop {a['name']} starting with Windows on {h}")
            up = self.ctx.read_data("endpoint.updates", {"host": h}) or {}
            if up.get("cache_corrupt"):
                self.change("endpoint.updates.reset_cache", {"host": h}, f"reset Windows Update cache on {h}")
            if up.get("pending"):
                self.change("endpoint.updates.install", {"host": h}, f"install pending updates on {h}")
            df = self.ctx.read_data("endpoint.defender", {"host": h}) or {}
            for al in df.get("alerts", []):
                if al["status"] == "active":
                    self.change("endpoint.defender.quarantine", {"host": h, "alert_id": al["id"]},
                                f"quarantine {al['threat']} on {h}")
            if df.get("alerts") and df.get("definitions_age_days", 0) > 1:
                self.change("endpoint.defender.update_definitions", {"host": h}, f"update Defender on {h}")
            br = self.ctx.read_data("endpoint.browser", {"host": h}) or {}
            bad_ext = [x for x in br.get("extensions", []) if x.get("malicious")]
            for x in bad_ext:
                self.change("endpoint.browser.extension.remove", {"host": h, "extension": x["name"]},
                            f"remove malicious extension {x['name']} on {h}")
            if br and br.get("homepage") != HEALTHY_HOMEPAGE and (bad_ext or self.topic("homepage", "pop-up")):
                self.change("endpoint.browser.reset", {"host": h}, f"reset browser on {h}")
            if self.ctx.read_data("endpoint.outlook", {"host": h}) not in (None, "healthy"):
                self.change("endpoint.outlook.rebuild_profile", {"host": h}, f"rebuild Outlook profile on {h}")
            au = self.ctx.read_data("endpoint.audio", {"host": h}) or {}
            if au and not au.get("teams_mic_permission"):
                self.change("endpoint.teams.allow_microphone", {"host": h}, f"allow Teams microphone on {h}")
            if au and au.get("muted"):
                self.change("endpoint.audio.unmute", {"host": h}, f"unmute microphone on {h}")
            vpn = self.ctx.read_data("endpoint.vpn", {"host": h}) or {}
            if vpn.get("status") == "failed":
                net = net or self.ctx.read_data("network.info") or {}
                if net.get("vpn_server") and vpn["server"] != net["vpn_server"]:
                    self.change("endpoint.vpn.set_server", {"host": h, "server": net["vpn_server"]},
                                f"point VPN on {h} at {net['vpn_server']}")
            if self.topic("print"):
                printers = printers if printers is not None else {p["name"]: p for p in self.ctx.read_data("printers.list") or []}
                for ip in self.ctx.read_data("endpoint.printers", {"host": h}) or []:
                    p = printers.get(ip["name"])
                    if p and p["status"] == "ready" and ip["port_ip"] != p["ip"]:
                        self.change("endpoint.printer.set_port", {"host": h, "printer": ip["name"], "ip": p["ip"]},
                                    f"repoint {ip['name']} on {h} to {p['ip']}")
            if self.topic("admin access", "contractor", "admin rights"):
                extra = set(self.ctx.read_data("endpoint.local_admins", {"host": h}) or []) - EXPECTED_LOCAL_ADMINS
                if extra:
                    self.escalate(f"Unexpected local administrators on {h}: {', '.join(sorted(extra))}. Removing admin "
                                  "rights is a security change for a person.")

    def shared_service_checks(self):
        if self.topic("print") and not self.mentioned:
            for p in self.ctx.read_data("printers.list") or []:
                if p["status"].startswith("error") and self.ctx.read_data("printer.queue", {"printer": p["name"]}):
                    self.change("printer.queue.clear", {"printer": p["name"]}, f"clear the queue on {p['name']}")
        if self.topic("wi-fi", "wifi", "ip address", "internet"):
            d = self.ctx.read_data("network.dhcp") or {}
            if d and d["leases_used"] >= d["pool_size"]:
                self.change("network.dhcp.set_lease_hours", {"hours": 8}, "shorten DHCP leases to free addresses")
        if self.topic("website", "web site", "not private", "certificate"):
            site = self.ctx.read_data("web.site") or {}
            if site and site.get("cert_days_left", 99) < 14:
                self.change("web.certificate.renew", {}, "renew the website certificate")
            net = self.ctx.read_data("network.info") or {}
            for r in self.ctx.read_data("network.dns.list") or []:
                if r["name"] == "www" and net.get("web_server_ip") and r["value"] != net["web_server_ip"]:
                    self.escalate(f"The www DNS record points to {r['value']} instead of the web server "
                                  f"{net['web_server_ip']}. Changing public DNS is a security change for a person.")
        if self.topic("backup", "back up"):
            for j in self.ctx.read_data("backup.jobs") or []:
                if not j["enabled"] or j["last_result"] != "success":
                    self.change("backup.job.resume", {"job": j["name"]}, f"resume backup job {j['name']}")
