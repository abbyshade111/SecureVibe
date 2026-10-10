# Read 7z and rar archives in the upload check (V5.2.3)

**Status:** open

From the open part of 0029, part 15. Only zip and gzip are read. 7z and rar each need a reader of their own, and rar's format is proprietary, so this may stay a known limit. Decide first whether either is worth reading; the tar item comes before it.
