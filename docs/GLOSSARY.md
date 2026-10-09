# Words StackVet uses

StackVet's guide and reports use some words that people who do not program may not know. Each one is explained here
in a sentence or two, and the guide links here the first time it uses one.

## AI coding tool

A program that writes code for you when you describe what you want: Claude Code, GitHub Copilot in VS Code, Cursor,
and others. StackVet does not write code; it checks what the AI coding tool wrote.

## Terminal

A window where you type commands instead of clicking. On a Mac it is the app called Terminal; on Linux it is usually
called Terminal too. Most AI coding tools can also run commands in a terminal of their own.

## Folder path

Where a folder is on your computer, written out in full, such as `/Users/you/code/my-app`. In a terminal, `pwd`
("print working directory") prints the path of the folder you are in.

## Docker

A program that runs other programs in a sealed box of their own, called a [container](#container), so they cannot
change the rest of your computer. StackVet runs inside Docker. **Docker Desktop** is the version for Macs and Windows;
it has to be running (its whale icon in the menu bar) before your AI coding tool starts.

## Container

One sealed box that Docker runs. StackVet's container can read the one app folder it is given, and has no internet
connection.

## Image

The packed-up program Docker starts a container from. StackVet's image is `ghcr.io/abbyshade111/stackvet-sv`;
`docker pull` fetches it, and fetching it again brings it up to date.

## Homebrew

A free program for installing other programs on a Mac or on Linux, from the terminal. With it, `brew install`
installs StackVet on your own computer, which the checks of your running app need.

## Git

A program that keeps every saved version of the files in a folder, so changes can be seen and undone. A folder that git
looks after is a **repository**. `git init` makes one. StackVet checks a repository's history for passwords or keys
that were ever saved there, even if they were deleted later.

## MCP

The Model Context Protocol: a standard way for an AI coding tool to use another program's tools. StackVet is an **MCP
server**: once it is connected, your AI coding tool can call StackVet's tools, whose names start with `stackvet_`.

## Settings file

A small file in your app's folder that tells your AI coding tool how to start StackVet: `.mcp.json` for Claude,
`.vscode/mcp.json` for VS Code, `.cursor/mcp.json` for Cursor. `sv connect` prints one with the paths already right.

## `sv`

StackVet's command. You type `sv` and what you want, such as `sv check .` (check the app in this folder) or `sv
--version` (which StackVet this is).

## `stackvet.toml`

The file in your app's folder that says what your app does: who uses it, whether people sign in, whether it takes
uploads or payments, whether it uses AI. StackVet decides which security requirements apply from it. Your AI coding
tool writes it with you.

## Requirement

One thing a secure app must do, written by OWASP, a nonprofit that writes security standards. StackVet checks against
three of them: the **ASVS** (requirements for web apps, with numbers like V7.4.1), the **AISVS** (for apps that use
AI, with numbers like C7.1.1), and the **Secure by Design** checklist (decisions made before code is written).

## Check

One thing StackVet looks at: a pattern in the code, a setting, a package version, or how your running app answers.
One check can speak to several requirements, and one requirement may need several checks.

## Finding

Something a check found wrong, such as a password saved in the code. A finding says what was found and where, and
what to do about it.

## Not assessed

Nothing was checked, so nothing is known. StackVet never counts "not assessed" as passing. A report with few findings
is only good news when its list of what was not assessed is short too.

## Verified

A check produced evidence that a requirement is met. How strong that evidence is depends on how it was gathered:
reading the code, running the app, or a person's own answer.

## The running app

Your app started for real, in a container with no internet connection, so StackVet can send it requests and see
what it does: whether it refuses a wrong password, whether one user can read another's records. `sv report --run`
does this.

## Package

Code someone else wrote that your app uses, such as a library for sign-in. A **lockfile** (such as
`package-lock.json` or `poetry.lock`) records exactly which versions your app uses, so StackVet can look them up
against lists of known security problems.

## Report

What StackVet writes after a check, in a folder called `stackvet-report` in your app's folder: `compliance.md` to
read, `report.html` to open in a browser, and `report.json` for programs.
