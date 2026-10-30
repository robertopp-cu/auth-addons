===============================================
Authentication - Brute-Force Filter (Odoo 18.0)
===============================================

Description
===========

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

Configuration
=============

If Odoo runs behind a reverse proxy, set ``proxy_mode = True`` in
``odoo.conf`` and make the proxy send ``X-Forwarded-For``. Otherwise every
request will seem to come from the proxy.

You can use these system parameters (*Settings / Technical / Parameters /
System Parameters*) to control this addon:

* ``auth_brute_force.whitelist_remotes``: comma-separated list of whitelisted
  IPs or networks (e.g. ``203.0.113.45, 192.168.0.0/24``). Failures from these
  remotes are ignored.
* ``auth_brute_force.max_by_ip``: defaults to 50. Maximum successive failures
  allowed for an IP. After hitting the limit, the IP gets banned.
* ``auth_brute_force.max_by_ip_user``: defaults to 10. Maximum successive
  failures allowed for an IP and user combination. After hitting the limit,
  that user and IP combination is banned.
* ``auth_brute_force.window_minutes``: defaults to 0 (disabled). If set, only
  failures in the last N minutes are counted, so bans expire by themselves
  instead of lasting until an administrator unbans them.
* ``auth_brute_force.ban_minutes``: defaults to 0, which means that bans last
  until an administrator lifts them (or until failures leave the
  ``window_minutes`` window, if set). If greater than 0, bans are **timed**:
  this is the duration, in minutes, of the first ban.
* ``auth_brute_force.ban_increment_factor``: defaults to 2. Only with timed
  bans. Each new ban of the same remote (or remote+login) lasts
  ``ban_minutes * factor ** previous_bans``. With 10 minutes and factor 2:
  10, 20, 40, 80... Use 1 for fixed-length bans.
* ``auth_brute_force.ban_max_minutes``: defaults to 0 (no limit). Upper limit
  for the duration of a ban, e.g. 10080 for one week.
* ``auth_brute_force.ban_history_days``: defaults to 7. Only bans started in
  the last N days count as "previous bans" (0 = remember forever). Bans lifted
  manually by an administrator never count.
* ``auth_brute_force.check_remote``: defaults to ``False``. If ``True``, the
  module queries http://ip-api.com to show extra information about the remote
  IP. It sends the IP to a third party over plain HTTP, so it is off by
  default.

Recommended setup for an office that shares one public IP and fail2ban-like
behavior::

    base.login_cooldown_after          = 0       (Odoo's own per-IP cooldown)
    auth_brute_force.whitelist_remotes = <office public IP>
    auth_brute_force.max_by_ip_user    = 5
    auth_brute_force.window_minutes    = 10      (like fail2ban's findtime)
    auth_brute_force.ban_minutes       = 10
    auth_brute_force.ban_increment_factor = 2
    auth_brute_force.ban_max_minutes   = 10080

Usage
=====

Administrators can see the attempts in *Settings / Users & Companies /
Authentication Attempts*, unban a banned IP+login (use the most recent banned
attempt) and add or remove remotes from the whitelist.

With timed bans, *Settings / Users & Companies / Authentication Bans* lists
every ban with its start, end, duration and ban number, and lets you lift an
active one. Bans are created at the moment the limit is reached, not when the
next attempt arrives.

This module generates WARNING logs when a limit is reached:

* *Authentication failed from remote 'x.x.x.x'. The remote has been banned.
  Login tried: xxxx.*
* *Authentication failed from remote 'x.x.x.x'. The remote and login
  combination has been banned. Login tried: xxxx.*
* With timed bans: *Authentication failed from remote 'x.x.x.x'. The remote
  has been banned for N minutes (ban #M). Login tried: xxxx.*

Known issues / Roadmap
======================

* Old attempts are never purged. Add a scheduled cleanup for databases that
  receive a lot of bot traffic.
* Odoo's core login cooldown is per IP only; this could be reworked to be
  per IP+login in core.

Contributors
============

* Sylvain LE GAL (https://www.grap.coop)
* Jairo Llopis <jairo.llopis@tecnativa.com> (https://www.tecnativa.com)
* David Vidal <david.vidal@tecnativa.com> (https://www.tecnativa.com)
