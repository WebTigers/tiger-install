# tiger-install

**The one-file web installer for [Tiger](https://github.com/WebTigers/Tiger)** — install a modern,
multi-tenant CMS/SaaS platform on shared cPanel hosting with **no shell and no Composer**.

Download **one file**, drop it in your website's document root, open it in a browser. That's it.

```
public_html/tiger-install.php   →   open https://yourdomain.com/tiger-install.php
```

## What it does (and why it's safer than WordPress)

The old way — WordPress's `wp-config.php` with your database password sitting **in** the document
root — relies on the web server never serving `.php` as text. Tiger inverts that. This installer:

1. **Checks your host** meets Tiger's requirements (PHP 8.1+, `pdo_mysql`, `zip`, …) — a clear
   pass/fail list with the exact fix for anything short.
2. **Downloads the latest Tiger release** ZIP from GitHub and **verifies it** against the release's
   published `.sha256` (over TLS).
3. **Extracts the app _above_ your document root** — so your code and secrets are **not web-reachable
   at all**. Only a tiny front-controller shim + asset links go in the docroot.
4. **Writes your DB settings + freshly-minted secrets** into `local.ini` **above the docroot**,
   `chmod 600`.
5. **Builds the database schema** and **creates your admin account** — using Tiger's own installer, so
   nothing is re-implemented here.
6. **Deletes itself.**

The one thing **you** do by hand: create an empty MySQL database + user in cPanel's *MySQL Databases*
wizard (a normal cPanel DB account can't create a database from PHP — only you can, in cPanel). The
installer does everything else.

## Multi-domain (cPanel addon domains)

Each Tiger install is fully self-contained, so **one cPanel account can run many domains, each its own
independent install**:

```
/home/user/
├── domain.com/tiger-app/      ← install A (own code, own local.ini, own database)
├── domain.net/tiger-app/      ← install B
└── public_html/
    ├── domain.com/            ← install A document root
    └── domain.net/            ← install B document root
```

Upload the installer into a given domain's document root and it detects that domain automatically,
defaulting the app folder to `/home/user/<domain>/tiger-app` (editable). Repeat per domain.

## Evergreen — one file, never changes

This installer is **not** rebuilt per Tiger release. It resolves the **latest** Tiger release at
runtime and installs it. One permanent URL, forever:

```
https://raw.githubusercontent.com/WebTigers/tiger-install/main/tiger-install.php
```

To pin a specific version, add `?version=<tag>` when you open it.

## Requirements

Shared cPanel hosting with **PHP 8.1+** and the `pdo_mysql`, `zip`, `mbstring`, and
`openssl`/`sodium` extensions, plus `curl` (or `allow_url_fopen`) to download — the installer's first
screen verifies all of this and tells you what to toggle in cPanel. Full detail:
[Tiger INSTALL.md](https://github.com/WebTigers/Tiger).

## Security

- App + `local.ini` (secrets) live **above** the web root — never fetchable over HTTP.
- The download is **checksum-verified over TLS** before it's trusted.
- The installer **refuses to overwrite** an existing configured install and **self-deletes** on
  success (with a loud warning to delete it manually if it can't).
- It's **one small file** on purpose: read it top to bottom before you run it. That's the whole point
  of its own repo.

## Status

> **Beta.** This installer targets the **vendored full-app release bundle** (`tiger-<version>.zip` +
> `.sha256`) attached to [`WebTigers/tiger`](https://github.com/WebTigers) releases. Until that release
> artifact is published, use the **manual upload** path the installer offers, or the Composer install
> (`composer create-project webtigers/tiger my-app --stability=beta`).

## License

BSD-3-Clause © WebTigers. "Tiger" and "WebTigers" are trademarks of WebTigers. See [LICENSE](LICENSE).
