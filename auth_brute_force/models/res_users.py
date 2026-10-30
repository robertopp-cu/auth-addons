# Copyright 2017 Tecnativa - Jairo Llopis
# License AGPL-3.0 or later (https://www.gnu.org/licenses/agpl).

import logging
from contextlib import contextmanager
from threading import current_thread

from odoo import SUPERUSER_ID, api, models
from odoo.exceptions import AccessDenied
from odoo.http import request

_logger = logging.getLogger(__name__)


class ResUsers(models.Model):
    _inherit = "res.users"

    # Helpers to track authentication attempts
    @classmethod
    def _auth_attempt_remote(cls):
        """Remote IP of the current HTTP/RPC request, or ``False`` if none.

        Behind a reverse proxy, Odoo must run with ``proxy_mode = True`` for
        this to be the real client IP and not the proxy's one.
        """
        if request:
            try:
                return request.httprequest.environ.get("REMOTE_ADDR") or False
            except (AttributeError, RuntimeError):
                pass
        # RPC calls run without ``request``; see controllers/rpc.py
        return getattr(current_thread(), "auth_attempt_remote", False) or False

    @classmethod
    @contextmanager
    def _auth_attempt(cls, login):
        """Start an authentication attempt and track its state.

        Auth methods call each other (``authenticate()`` -> ``_login()`` ->
        ``_check_credentials()``), so only the outermost call creates the
        attempt and records its final result. Nested calls just join it.
        """
        thread = current_thread()
        if getattr(thread, "auth_attempt_id", False):
            # Nested call; the outermost one will record the result
            yield
            return
        attempt_id = cls._auth_attempt_new(login)
        if not attempt_id:
            # No attempt was created, so there's nothing to do here
            yield
            return
        thread.auth_attempt_id = attempt_id
        try:
            # Anything that is not a clear success counts as a failure
            result = "failed"
            try:
                yield
                result = "successful"
            except AccessDenied as error:
                result = getattr(error, "reason", "failed")
                raise
            finally:
                cls._auth_attempt_update({"result": result})
        finally:
            del thread.auth_attempt_id

    @classmethod
    def _auth_attempt_new(cls, login):
        """Store one authentication attempt, not knowing the result."""
        remote = cls._auth_attempt_remote()
        # Exit if it doesn't make sense to store this attempt
        if not remote:
            return False
        # Use a separate cursor to keep changes always
        with cls.pool.cursor() as cr:
            env = api.Environment(cr, SUPERUSER_ID, {})
            attempt = env["res.authentication.attempt"].create(
                {
                    "login": login,
                    "remote": remote,
                }
            )
            return attempt.id

    @classmethod
    def _auth_attempt_update(cls, values):
        """Update a given auth attempt if we still ignore its result."""
        auth_id = getattr(current_thread(), "auth_attempt_id", False)
        if not auth_id:
            return  # No running auth attempt; nothing to do
        # Use a separate cursor to keep changes always
        with cls.pool.cursor() as cr:
            env = api.Environment(cr, SUPERUSER_ID, {})
            attempt = env["res.authentication.attempt"].browse(auth_id)
            # Update only on 1st call
            if attempt.exists() and not attempt.result:
                attempt.write(values)

    @classmethod
    def _auth_attempt_ban_error(cls):
        error = AccessDenied()  # Generic message: don't tell attackers they are banned
        error.reason = "banned"
        return error

    @classmethod
    def _auth_attempt_assert_trusted(cls, login):
        """Raise ``AccessDenied`` if the current remote (or remote+login) is banned.

        This is done with its own cursor, so it can be called before the
        authentication code gets a cursor of its own.
        """
        remote = cls._auth_attempt_remote()
        if not remote:
            return
        with cls.pool.cursor() as cr:
            env = api.Environment(cr, SUPERUSER_ID, {})
            trusted = env["res.authentication.attempt"]._trusted(remote, login)
        if not trusted:
            raise cls._auth_attempt_ban_error()

    # Override auth-related core methods
    @classmethod
    def authenticate(cls, db, credential, user_agent_env):
        with cls._auth_attempt(credential.get("login")):
            return super().authenticate(db, credential, user_agent_env)

    @classmethod
    def _login(cls, db, credential, user_agent_env):
        login = credential.get("login")
        with cls._auth_attempt(login):
            # Check bans first, so no other auth module loaded after this one
            # (LDAP, OAuth...) can get around them
            cls._auth_attempt_assert_trusted(login)
            return super()._login(db, credential, user_agent_env)

    def _check_credentials(self, credential, env):
        """This is the most important and specific auth check method.

        When we get here, it means that Odoo already checked the user exists
        in this database. It is also the entry point for password checks that
        don't go through ``_login()`` (e.g. ``check()``, used by RPC calls,
        or password re-checks when changing sensitive settings).
        """
        login = self.env.user.login
        with self._auth_attempt(login):
            # Update login, in case the attempt stored another one
            self._auth_attempt_update({"login": login})
            remote = self._auth_attempt_remote()
            trusted = (
                self.env["res.authentication.attempt"].sudo()._trusted(remote, login)
            )
            # Fail if the remote is banned
            if not trusted:
                raise self._auth_attempt_ban_error()
            # Continue with other auth systems
            return super()._check_credentials(credential, env)
