# Copyright 2015 GRAP - Sylvain LE GAL
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl.html).

import ipaddress
import json
import logging
from datetime import timedelta
from urllib.request import urlopen

from odoo import api, fields, models

GEOLOCALISATION_URL = "http://ip-api.com/json/{}"
TRUE_VALUES = {"1", "true", "t", "yes", "y", "on"}

_logger = logging.getLogger(__name__)


class ResAuthenticationAttempt(models.Model):
    _name = "res.authentication.attempt"
    _description = "Authentication Attempt"
    _order = "create_date desc, id desc"

    login = fields.Char(string="Tried Login", index=True)
    remote = fields.Char(string="Remote IP", index=True)
    result = fields.Selection(
        string="Authentication Result",
        selection=[
            ("successful", "Successful"),
            ("failed", "Failed"),
            ("banned", "Banned"),
            ("unbanned", "Unbanned"),
        ],
        index=True,
    )
    remote_metadata = fields.Text(
        string="Remote IP metadata",
        compute="_compute_metadata",
        help="Metadata publicly available for remote IP",
    )
    whitelisted = fields.Boolean(
        compute="_compute_whitelisted",
    )

    @api.model
    def _get_param(self, key, default):
        return self.env["ir.config_parameter"].sudo().get_param(key, default)

    @api.depends("remote")
    def _compute_metadata(self):
        enabled = (
            str(self._get_param("auth_brute_force.check_remote", "False"))
            .strip()
            .lower()
            in TRUE_VALUES
        )
        for item in self:
            item.remote_metadata = False
            if not enabled:
                continue
            try:
                ipaddress.ip_address(item.remote)
            except ValueError:
                continue  # Never build a URL from something that is not an IP
            url = GEOLOCALISATION_URL.format(item.remote)
            try:
                res = json.loads(urlopen(url, timeout=5).read())  # noqa: S310
            except Exception:
                _logger.warning(
                    "Couldn't fetch details from %s",
                    url,
                    exc_info=True,
                )
            else:
                item.remote_metadata = "\n".join(f"{k}: {v}" for k, v in res.items())

    @api.model
    def _is_whitelisted(self, ip):
        if not ip:
            return False
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for whitelist in self._whitelist_remotes():
            try:
                # strict=False so that "192.168.0.5/24" is accepted too,
                # instead of being silently ignored
                if address in ipaddress.ip_network(whitelist, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def _compute_whitelisted(self):
        for one in self:
            one.whitelisted = self._is_whitelisted(one.remote)

    # Timed (and incremental) bans, enabled by ``auth_brute_force.ban_minutes``
    @api.model
    def _timed_bans_enabled(self):
        return int(self._get_param("auth_brute_force.ban_minutes", 0) or 0) > 0

    @api.model_create_multi
    def create(self, vals_list):
        records = super().create(vals_list)
        records._register_failures()
        return records

    def write(self, vals):
        result = super().write(vals)
        if vals.get("result") == "failed":
            self._register_failures()
        return result

    def _register_failures(self):
        """Ban remotes that just reached a limit, for the configured time."""
        failed = self.filtered(lambda one: one.result == "failed" and one.remote)
        if not failed or not self._timed_bans_enabled():
            return
        bans = self.env["res.authentication.ban"].sudo()
        for attempt in failed:
            remote, login = attempt.remote, attempt.login
            if self._is_whitelisted(remote):
                continue
            limit = int(self._get_param("auth_brute_force.max_by_ip", 50))
            if self._timed_failures(remote) >= limit:
                bans._ban(remote)
                continue
            limit = int(self._get_param("auth_brute_force.max_by_ip_user", 10))
            if login and self._timed_failures(remote, login) >= limit:
                bans._ban(remote, login)

    @api.model
    def _timed_failures(self, remote, login=None):
        """Failures of a remote (and login) that count towards a new ban.

        Failures before the last success, unban or ban don't count, and
        neither do the ones requests rejected while banned.
        """
        attempts = self.sudo()
        domain = [("remote", "=", remote)]
        if login is not None:
            domain.append(("login", "=", login))
        domain += attempts._window_domain()
        last_ok = attempts.search(
            domain + [("result", "in", ["successful", "unbanned"])],
            order="id desc",
            limit=1,
        )
        bans = self.env["res.authentication.ban"].sudo()
        ban_domain = [("remote", "=", remote)]
        if login is None:
            ban_domain.append(("login", "=", False))
        else:
            ban_domain += ["|", ("login", "=", False), ("login", "=", login)]
        last_ban = bans.search(ban_domain, order="last_attempt_id desc", limit=1)
        # Beware: ``id > False`` matches nothing in a domain, so use plain ints
        reset = max(last_ok.id or 0, last_ban.last_attempt_id or 0)
        return attempts.search_count(
            domain + [("id", ">", reset), ("result", "=", "failed")]
        )

    @api.model
    def _window_domain(self):
        window = int(self._get_param("auth_brute_force.window_minutes", 0) or 0)
        if window <= 0:
            return []
        since = fields.Datetime.now() - timedelta(minutes=window)
        return [("create_date", ">=", since)]

    @api.model
    def _hits_limit(self, limit, remote, login=None):
        """Know if a given remote hits a given limit.

        :param int limit:
            The maximum amount of failures allowed.

        :param str remote:
            The remote IP to search for.

        :param str login:
            If you want to check the IP+login combination limit, supply the
            login.
        """
        attempts = self.sudo()
        domain = [("remote", "=", remote)]
        if login is not None:
            domain.append(("login", "=", login))
        # Optional: only count failures inside a sliding time window
        domain += self._window_domain()
        # Find last successful login
        last_ok = attempts.search(
            domain + [("result", "in", ["successful", "unbanned"])],
            order="id desc",
            limit=1,
        )
        if last_ok:
            domain.append(("id", ">", last_ok.id))
        # Count failures since last success, if any
        recent_failures = attempts.search_count(
            domain + [("result", "in", ["failed", "banned"])]
        )
        # Did we hit the limit?
        return recent_failures >= limit

    @api.model
    def _trusted(self, remote, login):
        """Checks if any the remote or remote+login are trusted.

        :param str remote:
            Remote IP from which the login attempt is taking place.

        :param str login:
            User login that is being tried.

        :return bool:
            ``True`` means it is trusted. ``False`` means that it is banned.
        """
        # Cannot ban without remote
        if not remote:
            return True
        # Whitelisted remotes always pass
        if self._is_whitelisted(remote):
            return True
        # Timed bans are explicit records, created when the limit is reached
        if self._timed_bans_enabled():
            bans = self.env["res.authentication.ban"]
            if bans._is_banned(remote, login):
                _logger.info(
                    "Authentication rejected from banned remote '%s'. Login tried: %r.",
                    remote,
                    login,
                )
                return False
            return True
        # Check if remote is banned
        limit = int(self._get_param("auth_brute_force.max_by_ip", 50))
        if self._hits_limit(limit, remote):
            _logger.warning(
                "Authentication failed from remote '%s'. "
                "The remote has been banned. "
                "Login tried: %r.",
                remote,
                login,
            )
            return False
        # Check if remote + login combination is banned
        if login:
            limit = int(self._get_param("auth_brute_force.max_by_ip_user", 10))
            if self._hits_limit(limit, remote, login):
                _logger.warning(
                    "Authentication failed from remote '%s'. "
                    "The remote and login combination has been banned. "
                    "Login tried: %r.",
                    remote,
                    login,
                )
                return False
        # If you get here, you are a good boy (for now)
        return True

    @api.model
    def _whitelist_remotes(self):
        """Get whitelisted remotes.

        :return set:
            Remote IPs that are whitelisted currently.
        """
        whitelist = self._get_param("auth_brute_force.whitelist_remotes", "")
        return {item.strip() for item in whitelist.split(",") if item.strip()}

    def action_whitelist_add(self):
        """Add current remotes to whitelist."""
        whitelist = self._whitelist_remotes()
        whitelist |= set(self.mapped("remote"))
        self.env["ir.config_parameter"].sudo().set_param(
            "auth_brute_force.whitelist_remotes",
            ",".join(sorted(filter(None, whitelist))),
        )

    def action_unban(self):
        self.ensure_one()
        if self.result == "banned":
            self.write({"result": "unbanned"})
            # Also lift the timed bans (if any) that were rejecting it
            bans = self.env["res.authentication.ban"].sudo()
            bans.search(bans._active_domain(self.remote, self.login)).action_unban()

    def action_whitelist_remove(self):
        """Remove current remotes from whitelist."""
        whitelist = self._whitelist_remotes()
        whitelist -= set(self.mapped("remote"))
        self.env["ir.config_parameter"].sudo().set_param(
            "auth_brute_force.whitelist_remotes",
            ",".join(sorted(whitelist)),
        )
