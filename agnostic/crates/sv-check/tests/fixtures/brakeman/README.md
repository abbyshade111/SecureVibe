# Brakeman fixture

`brakeman-8.0.6.sarif` is the real output of Brakeman 8.0.6 run over `app/`, a small Rails app with one
of each kind of fault in it. `crates/sv-check/tests/adapters.rs` checks the rule map in
`data/adapters.json` against it, so the map is tested against what the tool writes rather than what its
documentation was read to say.

The run was made with these two files beside `app/config`, which Brakeman reads for the Rails version.
They are not kept here, so that the repository's dependency alerts do not report an old Rails pinned by
test data:

    # Gemfile
    source "https://rubygems.org"
    gem "rails", "7.1.3"

    # Gemfile.lock
    GEM
      remote: https://rubygems.org/
      specs:
        rails (7.1.3)

    PLATFORMS
      ruby

    DEPENDENCIES
      rails (= 7.1.3)

To regenerate: put them back in `app/`, then

    gem install brakeman -v 8.0.6
    cd app && brakeman --format sarif --output ../brakeman-8.0.6.sarif --no-progress --quiet .

Brakeman exits 3 when it finds warnings, which is expected here.
