# Copyright 2017 Tecnativa - Jairo Llopis
# License AGPL-3.0 or later (https://www.gnu.org/licenses/agpl).

from contextlib import contextmanager
from threading import current_thread

from odoo.http import request, route

from odoo.addons.base.controllers import rpc


@contextmanager
def _remote_in_thread():
    """Expose the remote IP while an RPC call runs.

    Odoo dispatches RPC calls with the HTTP request borrowed away from the
    request stack (``odoo.http.borrow_request``), so ``request`` is not
    available inside ``res.users.authenticate()``. Without this, XML-RPC and
    JSON-RPC logins could never be tracked nor banned.
    """
    thread = current_thread()
    thread.auth_attempt_remote = request.httprequest.environ.get("REMOTE_ADDR")
    try:
        yield
    finally:
        thread.auth_attempt_remote = None


class RPC(rpc.RPC):
    def _xmlrpc(self, service):
        # Used by both /xmlrpc/<service> and /xmlrpc/2/<service>
        with _remote_in_thread():
            return super()._xmlrpc(service)

    @route()
    def jsonrpc(self, service, method, args):
        with _remote_in_thread():
            return super().jsonrpc(service, method, args)
