# README assets

[Back to the project](../../README.md)

- `header-light.svg` and `header-dark.svg`: original gateway mark and wordmark
  for secure-setup. The README selects the variant with a picture element.
- `network.svg`: the default Cloudflare IP-range topology, with the optional
  outbound tunnel path described below it. All labels are editable SVG text.
- `wizard.png`: a screenshot of the actual connection form emitted by a
  local development build of secure-setup from commit `ae83128`.
- `wizard.cast`: the original asciinema v2 terminal-output recording behind
  the screenshot. It contains the documentation address `203.0.113.10` and
  no credentials or real server identifiers.

## Wizard capture

The binary was built with `go build` and run in a 100-column, 34-row
pseudo-terminal with `TERM=xterm-256color`, `COLORTERM=truecolor`, `NO_COLOR`
unset and a dark background. The example address was typed into the first
form. The form was never submitted; the process was stopped with Ctrl+C
before any connection, plan save or server change.

The recorded output was replayed unchanged in xterm.js 6.0.0 and captured
with Chromium through Playwright. The terminal viewport was sized to the
last occupied row plus one blank row. Prompt text, selections and colors
were not recreated or retouched. The image shows a `dev` build, not a
completed setup run.

To refresh it, build the current CLI, record the connection form with
asciinema or a pseudo-terminal, and stop before submitting the form. Use an
example address, keep the raw output, replay it in a terminal emulator, and
capture that terminal at a readable size. Check the PNG against the
recording before replacing both files. Do not insert fabricated success
output or real credentials into documentation images.

These assets are covered by the repository's [MIT license](../../LICENSE).
