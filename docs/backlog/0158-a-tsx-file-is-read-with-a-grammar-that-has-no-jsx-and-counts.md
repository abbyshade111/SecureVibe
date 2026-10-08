# A `.tsx` file is read with a grammar that has no JSX, and counts as read

**Status:** done, struck through in the old file, as its markers read on 8 October 2026

Done on 25 September
2026. `<button onClick={() => eval(q)}>` in a `.tsx` file was not found, and the report then listed
V1.3.2 as *checked (ast.dynamic-code-execution over 1 typescript file)*. `.tsx` is now parsed with the
TSX grammar, each rule's `typescript` query compiled a second time against it. And whatever the
grammar, a file whose parse holds an error lands in `AstScan::unparsed_files`: its findings stand, but
no rule that reads code may claim a clean result while it is there, and `sv check` and the report say
which files. Breaking either half turns two or three tests red. `.jsx` needed nothing: the JavaScript
grammar reads JSX.
