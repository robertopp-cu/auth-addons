This module registers each request done by users trying to authenticate into
Odoo (web login, XML-RPC and JSON-RPC). If the authentication fails, a counter
is increased for the given remote IP and for the IP+login combination. After a
defined number of failures, Odoo will ban that IP or that IP+login pair and
ignore new requests.

Banning is done per IP+login by default, so one user mistyping a password does
not lock out other users who share the same public IP (e.g. an office behind
NAT).

Optionally, bans can be timed and **incremental**, like fail2ban's
``bantime.increment``: the first ban lasts a few minutes, and every time the
same IP (or IP+login) misbehaves again the ban lasts longer.

When a user is banned, the request is considered an attack, so the UI does
**not** say that the user is banned: the regular *Wrong login/password*
message is displayed instead.

Note that Odoo itself has a basic login cooldown (``base.login_cooldown_after``
and ``base.login_cooldown_duration`` system parameters) that counts failures
**per IP only**, in memory, and only for web logins. If you share one public IP
among many users, consider setting ``base.login_cooldown_after`` to ``0`` and
letting this module do the job.
