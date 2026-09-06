# What is this?

The space has Jellyfin with movies, qBittorrent for downloads, and Nextcloud for files.

Previously, whenever someone needed access, an admin had to create three accounts and dictate three passwords. Passwords got lost, ended up in the wrong hands, and lived forever — even after someone stopped being a resident long ago.

`akiba-gate` gets rid of all that. A resident opens the portal, clicks **"Sign in with Telegram"**, and then simply clicks a service card. That's it.

## What it feels like

Click Jellyfin — your media library opens, already signed in.

Click Nextcloud — wait a couple of seconds, and your files are there.

No login forms, no passwords, nothing to remember.

And if an admin disables access, the card simply disappears. It's not "the password stopped working" — there is simply no access anymore.

## Why this is safe

The gateway **cannot issue access tokens**. Tokens are signed by a separate service; the gateway only has the public key. It can verify a signature, but it cannot forge one.

It also doesn't know or store the resident's password.

For Nextcloud, an account is created with a random password that is immediately forgotten. Authentication through the portal uses a one-time code that is valid for sixty seconds and is destroyed after the first use.

A resident can set any password they want in Nextcloud — it has absolutely no effect on portal authentication.

## What's under the hood

A single Go binary with no external dependencies. Inside:

* token verification and service access control (SQLite, just a few lines of schema);
* three different authentication methods, one for each service — not because we wanted it that way, but because Jellyfin, qBittorrent, and Nextcloud work differently;
* a reverse proxy for Jellyfin and qBittorrent, allowing them to run under the same public address as the portal;
* a bot that posts in the chat who added what to the download queue.

## What you need to run it

An external `auth-service` with Telegram authentication, the three services, and a single publicly exposed port.

Everything else is documented in [README.md](README.md) and [DEPLOY.md](DEPLOY.md).