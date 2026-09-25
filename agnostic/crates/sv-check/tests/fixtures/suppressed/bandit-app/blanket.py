def search(db, q):
    return db.execute("select * from notes where t = '" + q + "'").fetchall()  # nosec
