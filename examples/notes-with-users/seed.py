"""Creates the accounts `sv run` signs in as, from the variables it passes in."""

import os
import secrets

from app import db, hash_password

with db() as conn:
    for user, password, admin in (
        (os.environ["SV_USER_A"], os.environ["SV_PASSWORD_A"], 0),
        (os.environ["SV_USER_B"], os.environ["SV_PASSWORD_B"], 0),
        (os.environ.get("SV_ADMIN"), os.environ.get("SV_ADMIN_PASSWORD"), 1),
    ):
        if user:
            salt = secrets.token_hex(16)
            conn.execute(
                "insert or replace into users values (?, ?, ?, ?)",
                (user, hash_password(password, salt), salt, admin),
            )
