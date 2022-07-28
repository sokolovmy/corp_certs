import hashlib
import sqlite3
from datetime import datetime, timezone
from config import db_file_name


_create_certs_db_sql_ = '''
CREATE TABLE IF NOT EXISTS certs (
    id varchar(255) PRIMARY KEY,
    cert text UNIQUE,
    hosts text
);
'''


class CacheDB:
    def __init__(self, dbFileName=db_file_name):
        self.con = sqlite3.connect(dbFileName)
        self._initDB()

    def __del__(self):
        self.con.close()

    def _initDB(self):
        cur = self.con.cursor()
        cur.executescript(_create_certs_db_sql_)
        self.con.commit()

    def _execSQL(self, SQL, params=None, commit=True, fetchResult=True):
        cur = self.con.cursor()
        if params:
            cur.execute(SQL, params)
        else:
            cur.execute(SQL)
        res = None
        if fetchResult:
            res = cur.fetchall()
        cur.close()
        self.commit(commit)
        return res

    def commit(self, commit=True):
        if commit:
            self.con.commit()

    def addCert(self, certStr, hosts, commit=False):
        if type(hosts) is list:
            hosts = ', '.join(hosts)
        id = hashlib.md5(certStr.encode()).hexdigest()
        self._execSQL(
            "INSERT INTO certs (id, cert, hosts) VALUES (?, ?, ?)",
            (id, certStr, hosts,),
            fetchResult=False,
            commit=commit
        )
        return id

    def flushCertsTable(self, commit=False):
        self._execSQL("DELETE FROM certs", commit=commit)

    def getCertById(self, id):
        res = self._execSQL("SELECT cert, hosts FROM certs WHERE id = ?", (id,))
        return res[0]

    def getCerts(self):
        return self._execSQL("SELECT id, cert, hosts FROM certs")
