# Two checks that rested on one sample (ADR-055)

The recipe trial found two checks whose answer depended on one choice of `sv`'s. The common-password check tried one
word, so a list written from memory passed or failed by whether it held that word; it now tries three of the same
shape from across the top 3000, sharing one random control, and credits only when all three are refused. The
cross-site check asked only the health path, while the harm it guards against lives behind sign-in; the first test
user now asks each private page the same question, and a page that echoes another site's Origin is a finding.
