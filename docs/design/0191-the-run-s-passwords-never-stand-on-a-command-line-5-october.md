# The run's passwords never stand on a command line (5 October 2026)

A third part of the deep review's improvement 5. `sv run` hands the owner's `seed` command the run's test accounts,
their passwords, and their two-factor secrets, and hands the test sign-in provider its client secret. Each went to
`docker` as `-e NAME=value`, on its command line, which any other user of the computer can read while it runs.

- **By name only.** `seed_args` and `provider_start` name each secret with `-e NAME` and no value, and
  `docker_with_secrets` puts the values in the Docker program's own environment, from where Docker copies each into
  the container. A process's environment is readable only by its own user.
- The review suggested standard input; the environment does the same with nothing for the seed command to read, so
  every seed written for the variables keeps working.

How it is held: `no_password_or_secret_stands_on_docker_s_command_line`, over every variable the seed is given and
the provider's secret, and, with a real container, `the_seed_command_is_given_the_passwords_though_they_are_not_on_the_command_line`
and `the_test_provider_is_given_its_secret_though_it_is_not_on_the_command_line`, each with a control that a wrong
value is refused (`crates/sv-run/src/docker.rs`). Four guards were undone in turn and each was caught.
