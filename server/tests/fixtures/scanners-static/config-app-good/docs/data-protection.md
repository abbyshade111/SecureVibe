# The information this app holds

This app holds the accounts of the people who sign in, and the records they create. Sign-in details are stored as
hashes, never as readable text, and sensitive fields are encrypted before they are written to the database.

| Kind of information | How it is protected | How long it is kept |
| --- | --- | --- |
| Account details | Hashed passwords, encrypted one-time-code seeds | Until the account is deleted |
| Records people create | Encrypted sensitive fields | Until deleted by their owner |

Deleting an account deletes the records that belong to it.
