# Who Pandora's web interface is for

Guidance from the maintainers (review of the web UI rework, PR #1055, November 2026). Every interface decision
should be checked against it.

## The core use case

A **non-technical user** (think a bank employee) receives a file, or a link pointing to a file
(in which case: Lookyloo first, then Pandora). They need to **see what is in it, because it is their job**.

It makes sense to have many more modules, YARA rules and so on. But down the line, if they expect a PDF of a
passport to get the name of a customer, and they get that, they can copy it from the preview, possibly download
the image, and go on.

So:

- **The content comes first.** The preview is the product: the user should be able to read it, copy from it and
  download it, and move on **without ever opening the original file**.
- **Modules, rules and verdicts are supporting information.** They stay available, lower on the page, for the
  people who need them.
- **An "open the file" action is not a goal.** The page succeeds when the user does not need the file anymore.

## When there is no preview

If the file is, for example, an executable, there is nothing to read. The user must be told clearly:

- that **no preview is available**, and
- that they **must not open the file** before talking to someone (their security team / the administrator).

## Emails

For an email, what matters is:

- **the content of the mail** (the preview of its body),
- **the links** in it, which the user can send to Lookyloo **on demand, never automatically**,
- **information about the sender** (who it claims to come from, and what can be checked).

## Where the interface stands (November 2026)

| Goal | Status |
|---|---|
| Preview first, verdict lower | Done: file header → pages → analysis result |
| Read the content without opening the file | Done: pages at reading size, "Read the file here" guidance |
| Download the image / the text | Done: "Download the pages (images, ZIP)", "Download the text" |
| Copy text from the preview | Partly: "Text preview" block with "Copy all the text"; the page images themselves are not selectable |
| No preview → clear "do not open, talk to someone" message | Done |
| Email: body readable | Done |
| Email: links, send to Lookyloo on demand | Done: note above the body with the number of links, "Open it safely in Lookyloo" on each link, for everyone who can read the report |
| Email: all links at once, search a hostname / IP / URL in Lookyloo | Done: "Open the N links in Lookyloo" and "Search in Lookyloo", new tab, on click only |
| HTML file → Lookyloo on demand | Done: button above the pages |
| HTML body of an email → Lookyloo | To do (backend): the Lookyloo module only accepts HTML files |
| Email: sender information | Partly: From / To / Subject / Hops / SPF with a "headers can be forged" warning; no clearer summary |
| Email: attachments next to the body | To do: only in the "Extracted" tab |
