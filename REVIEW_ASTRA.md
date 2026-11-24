# Pre-public security review

**Verdict — SHIP.** The macOS and Linux offline examples previously downloaded the catalog as part of the command. Local documentation fix `76e27b229599c0c2c01401cf685d42e37fa34532` moves acquisition into the preparation instructions. All three offline command blocks now use only the saved catalog. The review started at `3942f17dd3d1075eb400309defa43f7b992e7f8b`.

| Check | Evidence |
| --- | --- |
| Files and history | Inspected the working files, workflow token references, Git blobs and commit metadata. Found no embedded credential, internal hostname or IP, workstation path, or workstation email. Commit identities use GitHub noreply addresses. |
| Offline mode | Any supplied `--file` value selects the local reader. All three offline unit tests passed, including empty-path and malformed-input cases. An independent CLI check observed zero Python socket, URL-request or subprocess events with a saved catalog, invalid JSON and an HTTPS URL passed as a filename. The latter two failed locally. |
| Online mode | Source inspection found two fixed HTTPS feed URLs, the CISA feed and its GitHub mirror. Requests use a 30-second timeout and the redirect handler permits only the two listed URLs. |
| Checksums | `shasum -a 256 -c SHA256SUMS` passed for `kev_check.py`. The fix touched only the README. |
| README | `--file`, `--days` and `--vendors` match the CLI. The default window includes today and the preceding six calendar days. Vendor words highlight matching entries in the list. |
| Reporting and license | `SECURITY.md` directs sensitive reports to GitHub private vulnerability reporting and contains no personal email. The MIT license is present. |

This review used local files and Git objects. Live feed availability, release download links and the hosted reporting form were outside the local checks. Signed tags were intentionally omitted.
