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
