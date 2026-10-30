# Copyright 2017 Tecnativa - Jairo Llopis
# License AGPL-3.0 or later (https://www.gnu.org/licenses/agpl).

import re
from datetime import timedelta

from odoo import fields
from odoo.tests.common import HttpCase, tagged
from odoo.tools import mute_logger

from ..models import res_authentication_attempt, res_users

GARBAGE_LOGGERS = (
    "werkzeug",
    "odoo.addons.base.models.res_users",
    res_authentication_attempt.__name__,
    res_users.__name__,
)
LOCAL = "127.0.0.1"


class BruteForceBase(HttpCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.Attempt = cls.env["res.authentication.attempt"]
        cls.password = "Good$%02584-pass"
        group_user = cls.env.ref("base.group_user")
        cls.user_a = cls.env["res.users"].create(
            {
                "name": "BF user A",
                "login": "bf_user_a",
                "password": cls.password,
                "groups_id": [(6, 0, group_user.ids)],
            }
        )
        cls.user_b = cls.env["res.users"].create(
            {
                "name": "BF user B",
                "login": "bf_user_b",
                "password": cls.password,
                "groups_id": [(6, 0, group_user.ids)],
            }
        )

    def setUp(self):
        super().setUp()
        icp = self.env["ir.config_parameter"].sudo()
        icp.set_param("auth_brute_force.max_by_ip_user", 3)
        icp.set_param("auth_brute_force.max_by_ip", 50)
        icp.set_param("auth_brute_force.window_minutes", 0)
        icp.set_param("auth_brute_force.ban_minutes", 0)
        icp.set_param("auth_brute_force.ban_increment_factor", 2)
        icp.set_param("auth_brute_force.ban_max_minutes", 0)
        icp.set_param("auth_brute_force.ban_history_days", 7)
        icp.set_param("auth_brute_force.whitelist_remotes", "")
        # Odoo's own cooldown is per-IP only and would interfere with tests
        icp.set_param("base.login_cooldown_after", 0)
        self.Attempt.search([]).unlink()

    # Helpers
    def _web_login(self, login, password):
        """Try to login through the web form; return if it worked."""
        self.url_open("/web/session/logout")
        page = self.url_open("/web/login")
        token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
        response = self.url_open(
            "/web/login",
            data={"login": login, "password": password, "csrf_token": token},
        )
        return "/web/login" not in response.url

    def _rpc_login(self, login, password):
        return bool(
            self.xmlrpc_common.authenticate(self.env.cr.dbname, login, password, {})
        )

    def _attempts(self, **domain):
        return self.Attempt.search([(k, "=", v) for k, v in domain.items()])

    def _trusted(self, login, remote=LOCAL):
        return self.Attempt._trusted(remote, login)


@tagged("post_install", "-at_install")
class BruteForceCase(BruteForceBase):
    # Web login
    @mute_logger(*GARBAGE_LOGGERS)
    def test_web_login_existing(self):
        """One user failing gets banned; the other user is not affected."""
        for _n in range(3):
            self.assertFalse(self._web_login("bf_user_a", "wrong"))
        self.assertFalse(self._trusted("bf_user_a"))
        self.assertTrue(self._trusted("bf_user_b"))
        # Even knowing the password, user A is rejected now
        self.assertFalse(self._web_login("bf_user_a", self.password))
        self.assertEqual(len(self._attempts(result="failed", login="bf_user_a")), 3)
        self.assertEqual(len(self._attempts(result="banned", login="bf_user_a")), 1)
        # ...but user B, from the very same IP, can work normally
        self.assertTrue(self._web_login("bf_user_b", self.password))

    @mute_logger(*GARBAGE_LOGGERS)
    def test_web_login_ip_banned(self):
        """Too many failures from one IP ban every login from it."""
        self.env["ir.config_parameter"].sudo().set_param(
            "auth_brute_force.max_by_ip", 4
        )
        for _n in range(3):
            self.assertFalse(self._web_login("bf_user_a", "wrong"))
        self.assertTrue(self._trusted("bf_user_b"))
        self.assertFalse(self._web_login("bf_user_a", self.password))  # 4th failure
        # Now the whole IP is banned, including user B
        self.assertFalse(self._trusted("bf_user_b"))
        self.assertFalse(self._web_login("bf_user_b", self.password))

    @mute_logger(*GARBAGE_LOGGERS)
    def test_web_login_unexisting(self):
        """Fake logins are tracked and banned, without affecting real users."""
        for _n in range(3):
            self.assertFalse(self._web_login("nobody", self.password))
        self.assertFalse(self._trusted("nobody"))
        self.assertTrue(self._trusted("bf_user_a"))
        self.assertTrue(self._web_login("bf_user_a", self.password))
        self.assertEqual(len(self._attempts(result="failed", login="nobody")), 3)

    @mute_logger(*GARBAGE_LOGGERS)
    def test_web_login_unban(self):
        """An admin can unban a banned remote+login."""
        for _n in range(3):
            self.assertFalse(self._web_login("bf_user_a", "wrong"))
        self.assertFalse(self._web_login("bf_user_a", self.password))
        banned = self._attempts(result="banned", login="bf_user_a")
        self.assertEqual(len(banned), 1)
        self.assertFalse(banned.whitelisted)
        banned.action_unban()
        self.assertEqual(banned.result, "unbanned")
        self.assertTrue(self._web_login("bf_user_a", self.password))

    @mute_logger(*GARBAGE_LOGGERS)
    def test_web_login_whitelist(self):
        """Whitelisted remotes are never banned."""
        for _n in range(3):
            self.assertFalse(self._web_login("bf_user_a", "wrong"))
        self.assertFalse(self._web_login("bf_user_a", self.password))
        banned = self._attempts(result="banned", login="bf_user_a")
        banned.action_whitelist_add()
        self.assertTrue(banned.whitelisted)
        self.assertTrue(self._web_login("bf_user_a", self.password))
        banned.action_whitelist_remove()
        self.assertFalse(banned.whitelisted)

    @mute_logger(*GARBAGE_LOGGERS)
    def test_success_resets_counter(self):
        """A success in between resets the failure counter."""
        for _n in range(2):
            self.assertFalse(self._web_login("bf_user_a", "wrong"))
        self.assertTrue(self._web_login("bf_user_a", self.password))
        for _n in range(2):
            self.assertFalse(self._web_login("bf_user_a", "wrong"))
        self.assertTrue(self._trusted("bf_user_a"))
        self.assertTrue(self._web_login("bf_user_a", self.password))

    # XML-RPC
    @mute_logger(*GARBAGE_LOGGERS)
    def test_xmlrpc_login_existing(self):
        for _n in range(3):
            self.assertFalse(self._rpc_login("bf_user_a", "wrong"))
        self.assertFalse(self._trusted("bf_user_a"))
        self.assertTrue(self._trusted("bf_user_b"))
        self.assertFalse(self._rpc_login("bf_user_a", self.password))
        self.assertEqual(len(self._attempts(result="failed", login="bf_user_a")), 3)
        self.assertEqual(len(self._attempts(result="banned", login="bf_user_a")), 1)
        self.assertTrue(self._rpc_login("bf_user_b", self.password))
        # Unban
        self._attempts(result="banned", login="bf_user_a").action_unban()
        self.assertTrue(self._rpc_login("bf_user_a", self.password))

    @mute_logger(*GARBAGE_LOGGERS)
    def test_xmlrpc_login_unexisting(self):
        for _n in range(3):
            self.assertFalse(self._rpc_login("nobody", self.password))
        self.assertFalse(self._trusted("nobody"))
        self.assertTrue(self._rpc_login("bf_user_a", self.password))
        self.assertEqual(len(self._attempts(result="failed", login="nobody")), 3)
        self.assertEqual(len(self._attempts(result="banned", login="nobody")), 0)

    # ORM: no HTTP request, so no remote and nothing to ban
    @mute_logger(*GARBAGE_LOGGERS)
    def test_orm_login(self):
        users = self.env["res.users"]
        credential = {"login": "bf_user_a", "password": "wrong", "type": "password"}
        for _n in range(5):
            with self.assertRaises(Exception):  # noqa: B017
                users.authenticate(self.env.cr.dbname, credential, {})
        self.assertEqual(self.Attempt.search_count([]), 0)
        self.assertTrue(self._trusted("bf_user_a"))
        credential["password"] = self.password
        auth_info = users.authenticate(self.env.cr.dbname, credential, {})
        self.assertEqual(auth_info["uid"], self.user_a.id)

    # Whitelist parsing
    def test_whitelist_cidr(self):
        icp = self.env["ir.config_parameter"].sudo()
        icp.set_param(
            "auth_brute_force.whitelist_remotes",
            " 203.0.113.45 , 192.168.0.5/24 ,, not-an-ip",
        )
        self.assertTrue(self.Attempt._is_whitelisted("203.0.113.45"))
        # Host bits set in the network must not make the entry useless
        self.assertTrue(self.Attempt._is_whitelisted("192.168.0.77"))
        self.assertFalse(self.Attempt._is_whitelisted("192.168.1.1"))
        self.assertFalse(self.Attempt._is_whitelisted("garbage"))
        self.assertFalse(self.Attempt._is_whitelisted(False))

    # Sliding window (optional feature)
    def test_window(self):
        self.Attempt.create(
            [
                {"login": "bf_user_a", "remote": "198.51.100.7", "result": "failed"}
                for _n in range(3)
            ]
        )
        self.assertFalse(self.Attempt._trusted("198.51.100.7", "bf_user_a"))
        # Make those failures old and enable a window
        old = fields.Datetime.now() - timedelta(minutes=120)
        self.env.cr.execute(
            "UPDATE res_authentication_attempt SET create_date = %s", (old,)
        )
        self.env.invalidate_all()
        icp = self.env["ir.config_parameter"].sudo()
        icp.set_param("auth_brute_force.window_minutes", 0)
        self.assertFalse(self.Attempt._trusted("198.51.100.7", "bf_user_a"))
        icp.set_param("auth_brute_force.window_minutes", 30)
        self.assertTrue(self.Attempt._trusted("198.51.100.7", "bf_user_a"))

    # Metadata lookup is opt-in
    def test_remote_metadata_disabled_by_default(self):
        attempt = self.Attempt.create({"login": "x", "remote": "8.8.8.8"})
        self.assertFalse(attempt.remote_metadata)


@tagged("post_install", "-at_install")
class TimedBanCase(BruteForceBase):
    """Timed bans with incremental duration, like fail2ban's bantime.increment."""

    REMOTE = "198.51.100.7"

    def setUp(self):
        super().setUp()
        self.Ban = self.env["res.authentication.ban"]
        self.Ban.search([]).unlink()
        self.icp = self.env["ir.config_parameter"].sudo()
        self.icp.set_param("auth_brute_force.ban_minutes", 10)

    # Helpers
    def _fail(self, login, times=1, remote=REMOTE):
        for _n in range(times):
            self.Attempt.create({"login": login, "remote": remote, "result": "failed"})

    def _expire(self, ban):
        ban.write({"date_end": fields.Datetime.now() - timedelta(minutes=1)})

    def _last_ban(self):
        return self.Ban.search([], limit=1)  # newest first

    def _ban_series(self, bans, login="bf_user_a"):
        """Get the duration of ``bans`` consecutive bans, expiring each one."""
        durations = []
        for _n in range(bans):
            self._fail(login, 3)
            ban = self._last_ban()
            durations.append(ban.duration)
            self.assertFalse(self.Attempt._trusted(self.REMOTE, login))
            self._expire(ban)
            self.assertTrue(self.Attempt._trusted(self.REMOTE, login))
        return durations

    # Model level
    @mute_logger(*GARBAGE_LOGGERS)
    def test_ban_created_when_limit_is_reached(self):
        self._fail("bf_user_a", 2)
        self.assertFalse(self.Ban.search([]))
        self._fail("bf_user_a")
        ban = self.Ban.search([])
        self.assertEqual(
            (ban.remote, ban.login, ban.count, ban.duration),
            (self.REMOTE, "bf_user_a", 1, 10),
        )
        self.assertEqual(ban.state, "active")
        self.assertFalse(self.Attempt._trusted(self.REMOTE, "bf_user_a"))
        # Other users and other IPs are not affected
        self.assertTrue(self.Attempt._trusted(self.REMOTE, "bf_user_b"))
        self.assertTrue(self.Attempt._trusted("203.0.113.9", "bf_user_a"))

    @mute_logger(*GARBAGE_LOGGERS)
    def test_incremental_duration(self):
        self.assertEqual(self._ban_series(4), [10, 20, 40, 80])
        self.assertEqual(self._last_ban().count, 4)

    @mute_logger(*GARBAGE_LOGGERS)
    def test_max_duration(self):
        self.icp.set_param("auth_brute_force.ban_max_minutes", 30)
        self.assertEqual(self._ban_series(4), [10, 20, 30, 30])

    @mute_logger(*GARBAGE_LOGGERS)
    def test_factor_one_gives_fixed_bans(self):
        self.icp.set_param("auth_brute_force.ban_increment_factor", 1)
        self.assertEqual(self._ban_series(3), [10, 10, 10])

    @mute_logger(*GARBAGE_LOGGERS)
    def test_custom_factor(self):
        self.icp.set_param("auth_brute_force.ban_increment_factor", 3)
        self.assertEqual(self._ban_series(3), [10, 30, 90])

    @mute_logger(*GARBAGE_LOGGERS)
    def test_history_expires(self):
        self._fail("bf_user_a", 3)
        ban = self._last_ban()
        ban.write(
            {
                "date_start": fields.Datetime.now() - timedelta(days=8),
                "date_end": fields.Datetime.now() - timedelta(days=8),
            }
        )
        self._fail("bf_user_a", 3)
        # The old ban is out of the 7 days of memory: starts over at 10
        self.assertEqual(self._last_ban().duration, 10)
        self.assertEqual(self._last_ban().count, 1)

    @mute_logger(*GARBAGE_LOGGERS)
    def test_unbanned_does_not_count_as_history(self):
        self._fail("bf_user_a", 3)
        ban = self._last_ban()
        ban.action_unban()
        self.assertEqual(ban.state, "unbanned")
        self.assertTrue(self.Attempt._trusted(self.REMOTE, "bf_user_a"))
        self._fail("bf_user_a", 3)
        self.assertEqual(self._last_ban().duration, 10)

    @mute_logger(*GARBAGE_LOGGERS)
    def test_remote_wide_ban(self):
        self.icp.set_param("auth_brute_force.max_by_ip", 4)
        self.icp.set_param("auth_brute_force.max_by_ip_user", 100)
        self._fail("bf_user_a", 2)
        self._fail("bf_user_b", 2)
        ban = self.Ban.search([])
        self.assertEqual(len(ban), 1)
        self.assertFalse(ban.login)
        # Every login from that IP is banned...
        self.assertFalse(self.Attempt._trusted(self.REMOTE, "anybody"))
        self.assertFalse(self.Attempt._trusted(self.REMOTE, None))
        # ...but other IPs are fine
        self.assertTrue(self.Attempt._trusted("203.0.113.9", "bf_user_a"))

    @mute_logger(*GARBAGE_LOGGERS)
    def test_whitelist(self):
        self.icp.set_param("auth_brute_force.whitelist_remotes", self.REMOTE)
        self._fail("bf_user_a", 6)
        self.assertFalse(self.Ban.search([]))
        self.assertTrue(self.Attempt._trusted(self.REMOTE, "bf_user_a"))

    @mute_logger(*GARBAGE_LOGGERS)
    def test_success_resets_counter(self):
        self._fail("bf_user_a", 2)
        self.Attempt.create(
            {"login": "bf_user_a", "remote": self.REMOTE, "result": "successful"}
        )
        self._fail("bf_user_a", 2)
        self.assertFalse(self.Ban.search([]))

    @mute_logger(*GARBAGE_LOGGERS)
    def test_window_limits_counted_failures(self):
        self._fail("bf_user_a", 2)
        old = fields.Datetime.now() - timedelta(minutes=120)
        self.env.cr.execute(
            "UPDATE res_authentication_attempt SET create_date=%s", (old,)
        )
        self.env.invalidate_all()
        self.icp.set_param("auth_brute_force.window_minutes", 30)
        self._fail("bf_user_a", 1)  # The 2 old failures don't count any more
        self.assertFalse(self.Ban.search([]))

    @mute_logger(*GARBAGE_LOGGERS)
    def test_rejected_requests_do_not_extend_or_restack_bans(self):
        self._fail("bf_user_a", 3)
        ban = self._last_ban()
        end = ban.date_end
        for _n in range(5):
            self.Attempt.create(
                {"login": "bf_user_a", "remote": self.REMOTE, "result": "banned"}
            )
        self.assertEqual(len(self.Ban.search([])), 1)
        self.assertEqual(ban.date_end, end)
        # Rejected requests are not failures either: once it expires, it's clean
        self._expire(ban)
        self.assertTrue(self.Attempt._trusted(self.REMOTE, "bf_user_a"))
        self._fail("bf_user_a", 2)
        self.assertEqual(len(self.Ban.search([])), 1)

    @mute_logger(*GARBAGE_LOGGERS)
    def test_attempt_unban_lifts_timed_ban(self):
        self._fail("bf_user_a", 3)
        rejected = self.Attempt.create(
            {"login": "bf_user_a", "remote": self.REMOTE, "result": "banned"}
        )
        self.assertFalse(self.Attempt._trusted(self.REMOTE, "bf_user_a"))
        rejected.action_unban()
        self.assertTrue(self.Attempt._trusted(self.REMOTE, "bf_user_a"))
        self.assertEqual(self._last_ban().state, "unbanned")

    def test_disabled_by_default(self):
        self.icp.set_param("auth_brute_force.ban_minutes", 0)
        self._fail("bf_user_a", 5)
        self.assertFalse(self.Ban.search([]))

    # End to end
    @mute_logger(*GARBAGE_LOGGERS)
    def test_web_login_escalating_bans(self):
        for _n in range(3):
            self.assertFalse(self._web_login("bf_user_a", "wrong"))
        ban = self.Ban.search([])
        self.assertEqual(
            (ban.remote, ban.login, ban.duration), (LOCAL, "bf_user_a", 10)
        )
        # Banned even with the right password; same IP, other user, is fine
        self.assertFalse(self._web_login("bf_user_a", self.password))
        self.assertTrue(self._web_login("bf_user_b", self.password))
        # Rejected requests didn't create more bans
        self.assertEqual(len(self.Ban.search([])), 1)
        # Ban over: user A can work again
        self._expire(ban)
        self.assertTrue(self._web_login("bf_user_a", self.password))
        # Repeat offence: twice as long this time, even after a success
        for _n in range(3):
            self.assertFalse(self._web_login("bf_user_a", "wrong"))
        self.assertEqual(self._last_ban().duration, 20)
        self.assertFalse(self._web_login("bf_user_a", self.password))

    @mute_logger(*GARBAGE_LOGGERS)
    def test_xmlrpc_escalating_bans(self):
        for _n in range(3):
            self.assertFalse(self._rpc_login("bf_user_a", "wrong"))
        ban = self.Ban.search([])
        self.assertEqual(ban.duration, 10)
        self.assertFalse(self._rpc_login("bf_user_a", self.password))
        self.assertTrue(self._rpc_login("bf_user_b", self.password))
        self._expire(ban)
        for _n in range(3):
            self.assertFalse(self._rpc_login("bf_user_a", "wrong"))
        self.assertEqual(self._last_ban().duration, 20)
