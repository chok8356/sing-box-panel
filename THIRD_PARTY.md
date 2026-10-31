# Third-party components

| Component | Version | Source | License | How it is used |
|---|---|---|---|---|
| sing-box | 1.14.4 | https://github.com/SagerNet/sing-box/tree/v1.14.4 | GPL-3.0-or-later; see upstream naming clause | not bundled: the installer downloads the official release binary and checks its pinned SHA-256 |
| Inter | 4.1 | https://github.com/rsms/inter/tree/v4.1 | SIL Open Font License 1.1 | embedded in the panel binary; license at `internal/panel/static/Inter-LICENSE.txt` |
| Remix Icon | v4.9.1 | https://github.com/Remix-Design/RemixIcon/tree/v4.9.1 | Remix Icon License v1.0 | selected SVG icons embedded in the panel templates and CSS; license at `internal/panel/static/Remix-LICENSE.txt` |

Go dependencies and their versions are recorded in `go.mod` and `go.sum`: the SQLite driver modernc.org/sqlite and golang.org/x/crypto (Let's Encrypt via autocert).
