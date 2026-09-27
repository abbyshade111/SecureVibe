# Security policy

This page is for problems in `sv` itself: the `sv` program, its MCP server (what an AI coding tool talks to), the
container image at `ghcr.io/abbyshade111/securevibe-sv`, and the data files in `data/` that decide what it checks.

## How to report a problem privately

Use GitHub's private reporting: on this repository's **Security** tab, choose **Report a vulnerability**, or go
straight to <https://github.com/abbyshade111/SecureVibe/security/advisories/new>. Only you and the repository's
owner can see the report, and the conversation about a fix stays private until it is published.

Please do not open a public issue for it. A public issue tells everyone about the problem before there is a fix.

What helps:

- what you ran (the command, or the MCP tool and what it was asked), and what happened;
- which `sv`: the commit you built it from (`git rev-parse HEAD` in your copy), or the image's fingerprint
  (`docker image inspect --format '{{.Id}}' ghcr.io/abbyshade111/securevibe-sv`) if you used the container;
- a small example app that shows it, if you have one.

**Never put a real key or password in a report**, not even one that has already leaked. If one did leak, change it
with the service that issued it first, then report.

## What counts

A vulnerability in `sv` is something that lets it be used against the person running it. For example:

- it reads or writes a file outside the folder it was given (the MCP server refuses `..` and symbolic links that lead
  outside it);
- it opens a network connection of its own (it is designed to open none);
- it runs code from the app it is checking, when it was not asked to (`--run` and `--tools` are the only ways it does);
- a report, or a message to the AI tool, shows a whole key or password (secrets are shown as their first four
  characters and their length);
- the published image is not what this repository builds.

A check that misses a problem in *your* app, or reports one that is not there, is a bug in `sv` rather than a
vulnerability, and a public issue is the right place for it. If the miss could make somebody believe an app is safe
when it plainly is not, reporting it privately is fine too.

## Which versions

Fixes go into `main` and the image tagged `latest`. There are no older releases of `sv` to patch.

SecureVibe v1, the earlier app that wrote a Node app from a questionnaire, is archived on the `v1` branch and at the
tags `v1-paper` and `v1-final`, and is not maintained. A report about it is still welcome through the same page.
