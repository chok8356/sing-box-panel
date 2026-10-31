# Panel interface

Keep the existing dark, neutral interface. Shared styles live in
`internal/panel/static/app.css`; templates use native HTML controls.

- Inter for interface text, monospace for JSON, logs and paths.
- `--control-height`: `2.25rem` on every device; `--control-font-size`: `0.875rem`.
- `--control-padding`: `0.75rem`; corners use the shared `--radius-sm` token.
- `--field-gap`: `0.5rem` between label, control and help text.
- `--form-gap`: `1.5rem` between fields; section padding and spacing: `1.5rem`.
- Checkboxes: `1rem`, corners `0.25rem`, Remix `check-line` SVG checkmark;
  labels provide the larger click area.
- Fields use `.field`; client names use `.name-field` with the same rules.
- Buttons use `.button`, with `.primary` for the main action and `.danger`
  for destructive actions. Inputs and buttons share size and corner tokens.
- Selects keep native keyboard/mobile behavior, with a padded chevron.
- Client presets open in a native dialog from the page heading. Loading only
  replaces the editor contents; Save applies them to subscriptions.
- Settings cards use `.settings-section`: a `.section-heading` header, then
  children spaced by `--form-gap`. Forms inside use `.access-form`.
- Sign-in uses the same components as the panel, without size overrides.
- Informational notices and copy feedback share a top-center toast, hidden after
  five seconds, with a bell icon, light background and dark text. Errors and
  notices requiring an action stay inline.
- Every interactive control has visible keyboard focus. Disabled states remain
  distinguishable. In forced-colors mode, use native checkbox/select rendering.

Responsive layouts change placement and wrapping, never control sizes or type.
Use `rem` for CSS sizes; preserve the panel's existing compact scale.
Change shared tokens or component rules before adding page-specific overrides.
Check sign-in, Settings and client forms at desktop and mobile widths.
