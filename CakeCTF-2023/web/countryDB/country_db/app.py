#!/usr/bin/env python3
import flask
import sqlite3

app = flask.Flask(__name__)

def db_search(code):
    try:
        with sqlite3.connect('database.db') as conn:
            cur = conn.cursor()
            sql = f"SELECT name FROM country WHERE code=UPPER('{code}')"
            print(sql)
            cur.execute(sql)
            found = cur.fetchone()
        return None if found is None else found[0]
    except:
        flask.abort(400, f"INVALID INJECTION {sql} ")

@app.route('/')
def index():
    return flask.render_template("index.html")

@app.route('/api/search', methods=['POST'])
def api_search():
    req = flask.request.get_json()
    print(f"req: {req}")
    if 'code' not in req:
        flask.abort(400, "Empty country code")

    code = req['code']
    print(code)
    print(len(code))
    
    if len(code) != 2 or "'" in code:
        flask.abort(400, "Invalid country code")
    
    name = db_search(code)
    if name is None:
        flask.abort(404, "No such country")

    return {'name': name}

if __name__ == '__main__':
    app.run(debug=False)
