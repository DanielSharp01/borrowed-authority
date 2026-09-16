# Borrowed authority slides

A Reveal.js presentation by Daniel Zsolnai about vulnerability chains across a web application and GCP services.

## Run locally

```sh
npm install
npm run dev
```

## Build the web presentation

```sh
npm run build
```

The static build is written to `dist/`.

## Export a PDF

Start the presentation, then open the print view:

```text
http://localhost:5173/?print-pdf
```

Use the browser's print dialog and select landscape orientation with no margins.

Press `S` while presenting to open the Reveal.js speaker view.

The title and subtitle alternatives are recorded in `TITLE_OPTIONS.md`.
