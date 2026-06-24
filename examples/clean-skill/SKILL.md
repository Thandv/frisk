---
name: markdown-toc
description: Generate a table of contents for a markdown file.
---

# Markdown TOC

Given a markdown file, collect its headings and emit a nested table of contents
linking to each section anchor.

## Workflow

1. Read the target file's headings (`#`, `##`, `###`).
2. Build anchor slugs from each heading.
3. Emit a bullet list, indented by heading depth.

No network access, no shell, no secrets — pure text transformation.
