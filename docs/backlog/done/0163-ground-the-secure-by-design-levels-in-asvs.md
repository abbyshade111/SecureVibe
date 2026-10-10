# Ground the Secure by Design levels in ASVS

**Status:** done, struck through in the old file, as its markers read on 8 October 2026

Done on 25 September 2026, with the owner's
agreement to the design. `data/sbd-asvs-crosswalk.json` maps each of the thirty-six controls to the
ASVS requirements that ask the same thing — seventeen have counterparts, thirty pairs in all — and
each pair carries a few words naming what the two share, which the citation guard holds against
both texts. `Frameworks::apply_crosswalk` sets a control's level to the lower of its derived level and
its counterparts' lowest, so it can only ever come into scope sooner; a control with no counterpart
is level 1, shown at every target. Every control records where its level came from, the report lists
the controls above the target with that basis instead of calling them "above the ASVS level", and a
satisfied check about a counterpart is shown beside the control as supporting evidence. Loading
refuses a crosswalk that leaves a control out or cites an id that does not exist.
