# License AGPL-3.0 or later (https://www.gnu.org/licenses/agpl).

import logging
from datetime import timedelta

from odoo import api, fields, models

_logger = logging.getLogger(__name__)

# Like fail2ban, cap the exponent so huge ban counts cannot overflow
MAX_EXPONENT = 20


class ResAuthenticationBan(models.Model):
    """A timed ban, created only when ``auth_brute_force.ban_minutes`` is set.

    The duration of each ban grows with the number of previous bans of the
    same remote (or remote+login), like fail2ban's ``bantime.increment``.
    """

    _name = "res.authentication.ban"
    _description = "Authentication Ban"
    _order = "id desc"

    remote = fields.Char(string="Remote IP", index=True, required=True)
    login = fields.Char(
        string="Banned Login",
        index=True,
        help="Empty means that every login from the remote IP is banned.",
    )
    date_start = fields.Datetime(
        string="Banned Since", default=fields.Datetime.now, required=True
    )
    date_end = fields.Datetime(string="Banned Until", index=True, required=True)
    count = fields.Integer(
        string="Ban Number",
        help="1 for the first ban of this remote/login, 2 for the next, etc.",
    )
    duration = fields.Integer(string="Duration (minutes)")
    unbanned = fields.Boolean(help="Manually lifted by an administrator.")
    last_attempt_id = fields.Integer(
        help="Failures recorded up to this attempt do not count for new bans."
    )
    state = fields.Selection(
        selection=[
            ("active", "Active"),
            ("expired", "Expired"),
            ("unbanned", "Unbanned"),
        ],
        compute="_compute_state",
    )

    @api.depends("date_end", "unbanned")
    def _compute_state(self):
        now = fields.Datetime.now()
        for one in self:
            if one.unbanned:
                one.state = "unbanned"
            elif one.date_end and one.date_end > now:
                one.state = "active"
            else:
                one.state = "expired"

    @api.model
    def _active_domain(self, remote, login=None):
        """Domain of the bans that apply right now to remote (and login).

        Without ``login``, only bans of the whole remote are matched.
        """
        domain = [
            ("remote", "=", remote),
            ("unbanned", "=", False),
            ("date_end", ">", fields.Datetime.now()),
        ]
        if login:
            domain += ["|", ("login", "=", False), ("login", "=", login)]
        else:
            domain.append(("login", "=", False))
        return domain

    @api.model
    def _is_banned(self, remote, login=None):
        return bool(self.sudo().search_count(self._active_domain(remote, login)))

    @api.model
    def _get_param(self, key, default):
        return self.env["ir.config_parameter"].sudo().get_param(key, default)

    @api.model
    def _compute_duration(self, previous_bans):
        """Minutes for a ban, given how many bans came before it.

        ``ban_minutes * ban_increment_factor ** previous_bans``, capped at
        ``ban_max_minutes`` (0 = no cap). A factor of 1 gives fixed bans.
        """
        base = int(self._get_param("auth_brute_force.ban_minutes", 0) or 0)
        factor = float(self._get_param("auth_brute_force.ban_increment_factor", 2))
        factor = max(factor, 1.0)
        minutes = base * factor ** min(previous_bans, MAX_EXPONENT)
        cap = int(self._get_param("auth_brute_force.ban_max_minutes", 0) or 0)
        if cap > 0:
            minutes = min(minutes, cap)
        return max(1, int(round(minutes)))

    @api.model
    def _ban(self, remote, login=None):
        """Ban a remote (or a remote+login) if it isn't banned already."""
        bans = self.sudo()
        if bans.search_count(bans._active_domain(remote, login)):
            return bans.browse()
        history_days = int(self._get_param("auth_brute_force.ban_history_days", 7))
        history = [
            ("remote", "=", remote),
            ("login", "=", login or False),
            ("unbanned", "=", False),
        ]
        if history_days > 0:
            since = fields.Datetime.now() - timedelta(days=history_days)
            history.append(("date_start", ">=", since))
        previous = bans.search_count(history)
        minutes = bans._compute_duration(previous)
        now = fields.Datetime.now()
        last_attempt = (
            self.env["res.authentication.attempt"]
            .sudo()
            .search([], order="id desc", limit=1)
        )
        ban = bans.create(
            {
                "remote": remote,
                "login": login or False,
                "date_start": now,
                "date_end": now + timedelta(minutes=minutes),
                "count": previous + 1,
                "duration": minutes,
                "last_attempt_id": last_attempt.id,
            }
        )
        _logger.warning(
            "Authentication failed from remote '%s'. %s has been banned "
            "for %d minutes (ban #%d). Login tried: %r.",
            remote,
            "The remote" if not login else "The remote and login combination",
            minutes,
            previous + 1,
            login,
        )
        return ban

    def action_unban(self):
        self.write({"unbanned": True})
