from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from models import get_user, verify_user_password
from auth_limits import limit_attempts


auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/")
def index():
    if session.get("logged_in"):
        return redirect(
            url_for("dashboard.levels")
        )

    return redirect(
        url_for("auth.login")
    )


@auth_bp.route(
    "/login",
    methods=["GET", "POST"],
)
def login():
    if session.get("logged_in"):
        return redirect(
            url_for("dashboard.levels")
        )

    if request.method == "POST":
        username = request.form.get(
            "username",
            "",
        ).strip().lower()

        password = request.form.get(
            "password",
            "",
        )

        limit_attempts([
            ("login_ip", request.remote_addr or "unknown", current_app.config["LOGIN_IP_RATE_LIMIT"]),
            ("login_username", username[:128], current_app.config["LOGIN_USERNAME_RATE_LIMIT"]),
        ])

        user = get_user(username)

        if verify_user_password(
            user,
            password,
        ):
            session.clear()
            session.permanent = True

            session["logged_in"] = True
            session["username"] = user["username"]
            session["role"] = user["role"]

            return redirect(
                url_for("dashboard.levels")
            )

        flash(
            "Invalid username or password.",
            "error",
        )

    return render_template("login.html")


@auth_bp.route(
    "/logout",
    methods=["GET", "POST"],
)
def logout():
    session.clear()

    return redirect(
        url_for("auth.login")
    )
