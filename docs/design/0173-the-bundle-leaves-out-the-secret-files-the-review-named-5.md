# The bundle leaves out the secret files the review named (5 October 2026)

A6 of the deep review: `sv bundle` leaves out files by name, and each of these went into the zip: `prod.env`, `.envrc`,
`.pgpass`, `.docker/config.json`, `*.tfvars`, `*.tfstate`, `.kube/config`, and a `database.yml` with a password.

- **An environment file under any of its names**: `.env`, `.env.<anything>`, and now `<anything>.env`, with
  `example`, `sample`, `template`, or `dist` in its place still going in, since those show what to fill in; and
  `.envrc`.
- **Credential files by name**: `.pgpass`, `.my.cnf`, `.s3cfg`, `.boto`, beside the ones already listed.
- **Credential files by where they are**: Docker's `.docker/config.json` and Kubernetes' `.kube/config`, wherever in
  the app they sit. A `docker/config.json` or a `kube/deployment.yaml` is not one.
- **Terraform's variables and state**: `*.tfvars`, `*.tfvars.json`, and anything with `.tfstate` in its name,
  backups included. State holds every value Terraform created, in plain text.
- **A `database.yml` with a password written in it** stays out even when the credential scan does not flag it,
  which a short or simple password does not: a `password:` line with a value that is not read from the environment
  (`<%= ENV[...] %>`) or left empty.

How it is held: `every_secret_file_the_review_named_stays_out_and_its_shown_forms_go_in` and
`a_database_yml_with_a_password_written_in_it_stays_out` (`crates/sv-cli/src/bundle.rs`), and in
`crates/sv-cli/tests/bundle.rs` the app now carries a `config/database.yml` with a weak password and a `.kube/config`,
which must stay out of the zip, their contents nowhere in it. Six guards were undone in turn and each was caught, the
last only after the end-to-end case was added.
