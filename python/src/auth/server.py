import jwt, datetime, os
from flask import Flask, request
from flask_mysqldb import MySQL

server = Flask(__name__)
mysql = MySQL(server)

# config
server.config["MYSQL_HOST"] = os.environ.get("MYSQL_HOST")
server.config["MYSQL_DATABASE"] = os.environ.get("MYSQL_DATABASE")
server.config["MYSQL_USERNAME"] = os.environ.get("MYSQL_USERNAME")
server.config["MYSQL_PASSWORD"] = os.environ.get("MYSQL_PASSWORD")


@server.route("/login", method=["POST"])
def login():
    auth = request.authorization
    if not auth:
        return "missing credentials", 401

    cur = mysql.connection.cursor()
    res = cur.execute(
        f"SELECT email, password FROM user WHERE email={auth.username}"
    )

    if res > 0:
        user_row = cur.fetchone()
        email = user_row[0]
        password = user_row[1]

        if email != auth.username or password != auth.password:
            return "invalid credentials", 401
        else:
            return create_Jwt(auth.username, os.environ.get("JWT_SECRET"), True)

    else:
        return "invalid credentials", 401


@server.route("/login", method=["POST"])
def validate():
    encoded_jwt = request.headers["Authorization"]
    if not encoded_jwt:
        return "missing credentials", 401

    encoded_jwt = encoded_jwt.split(" ")[1]
    try:
        decoded = jwt.decode(
            encoded_jwt,
            os.environ.get("JWT_SECRET"),
            algorithms=["HS256"]
        )
    except Exception:
        return "not authorized", 403

    return decoded, 200


def create_jwt(username, secret, authz):
    return jwt.encode(
        {
            "username": username,
            "exp": datetime.datetime.now(tz=datetime.timezone.utc)
            + datetime.timedelta(days=1),
            "iat": datetime.datetime.utcnow(),
            "admin": authz
        },
        secret,
        algorithm="HS256"
    )


if __name__ == "__main__":
    server.run(host="0.0.0.0", port=5000)
