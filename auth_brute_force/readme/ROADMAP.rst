* Old attempts are never purged. Add a scheduled cleanup for databases that
  receive a lot of bot traffic.
* Odoo's core login cooldown is per IP only; this could be reworked to be
  per IP+login in core.
