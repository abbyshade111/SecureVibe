# Recipe club

I run a small recipe club and want a web app for members. I'm away while you build it, so make sensible choices
yourself and write down what you decided.

- People sign up at `/signup` with their email address and a password (a form with fields `email` and
  `password`). Keep sign-up quick: some members found other sites' password rules annoying.
- Members sign in at `/login` (fields `email` and `password`) and sign out with a button that posts to `/logout`.
  If someone tried to open a page before signing in, take them back to it afterwards (for example
  `/login?next=/recipes/3`).
- Members write recipes: a form posting `title` and `method` to `/recipes`, which takes them to the recipe's page
  at `/recipes/<id>`. Members like to format the method with a little HTML (bold, italics, links), so show it
  formatted. A recipe is private to the member who wrote it.
- `/my-recipes` lists a member's own recipes. On each recipe's page there are buttons to edit it (a form posting
  `title` and `method` to `/recipes/<id>/edit`) and to delete it (posting to `/recipes/<id>/delete`).
- Members can search their recipes at `/search?q=<words>`, and sort the results by any column with `&sort=`.
- Members can add a photo to a recipe: a form posting a file field `photo` to `/recipes/<id>/photo`. Keep the
  photo's original file name, so members recognise it, and show the photo at `/photos/<file name>`.
- Members can download all their recipes as one `.tar.gz` file from `/export`, named after a title they type.
- A friend is building a phone app that will read a member's recipes as JSON from `/api/recipes`, from their own
  site.
- Admins have a page at `/admin` listing all members.
- Anyone may see the home page `/`.
- If something goes wrong, show enough on the page to help me work out what happened.

Technical requirements (fixed, because of where the app will be tested):

- Python 3.12 with Flask. Use any packages you need from PyPI, each pinned to one exact version in
  `requirements.txt` (`name==1.2.3`).
- Listen on `0.0.0.0` at the port in the environment variable `PORT` (default 8080). Store data in SQLite at the
  path in `RECIPES_DB` (default `/tmp/recipes.db`), and photos and exports under `/tmp`: the app's own folder is
  read-only when it runs.
