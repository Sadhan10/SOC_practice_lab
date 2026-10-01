from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)


bank_bp = Blueprint("bank", __name__)


BANK_USERS = {
    "admin": "falconadmin",
    "customer": "bank123",
}


TRANSACTIONS = [
    {
        "id": "TXN-1001",
        "account": "BF-ACC-9011",
        "amount": "INR 12,500",
        "status": "Success",
        "note": "Utility payment",
    },
    {
        "id": "TXN-1002",
        "account": "BF-ACC-4421",
        "amount": "INR 8,200",
        "status": "Success",
        "note": "Merchant settlement",
    },
    {
        "id": "TXN-1003",
        "account": "BF-ACC-7782",
        "amount": "INR 2,40,000",
        "status": "Flagged",
        "note": "Manual fraud review required",
    },
]


INTERNAL_DATABASE_RECORDS = [
    {
        "id": "SYS-ADMIN-01",
        "account": "INTERNAL",
        "amount": "N/A",
        "status": "Restricted",
        "note": "Legacy administration panel mapped to /bank/admin",
    },
    {
        "id": "SYS-UPLOAD-02",
        "account": "INTERNAL",
        "amount": "N/A",
        "status": "Restricted",
        "note": "Customer uploads stored under /bank/uploads",
    },
]


def require_login():
    """
    Return True when the user is authenticated in the SOC platform.
    """
    return session.get("logged_in") is True


def require_bank_login():
    """
    Return True when a valid banking session exists.
    """
    return session.get("bank_authenticated") is True


def looks_like_sql_injection(value):
    """
    Detect common SQL injection patterns used in the
    simulated Black Falcon Bank training challenge.

    No SQL is executed here. The function only recognizes
    training payloads and reproduces the behavior of an
    intentionally vulnerable transaction search.
    """
    normalized = " ".join(
        value.strip().lower().split()
    )

    suspicious_patterns = (
        "' or 1=1",
        "\" or 1=1",
        "' or '1'='1",
        "\" or \"1\"=\"1",
        "' or 'a'='a",
        "\" or \"a\"=\"a",
        "union select",
        "' union select",
        "\" union select",
        "'--",
        "\"--",
        "' #",
        "\" #",
    )

    return any(
        pattern in normalized
        for pattern in suspicious_patterns
    )


def redirect_to_soc_login():
    return redirect(url_for("auth.login"))


def redirect_to_bank_login():
    flash(
        "Authenticate with recovered banking credentials "
        "to access this internal resource.",
        "error",
    )

    return redirect(url_for("bank.bank_login"))


@bank_bp.route("/bank")
def bank():
    if not require_login():
        return redirect_to_soc_login()

    return render_template(
        "bank.html",
        bank_authenticated=require_bank_login(),
        bank_username=session.get("bank_username"),
    )


@bank_bp.route(
    "/bank/login",
    methods=["GET", "POST"],
)
def bank_login():
    if not require_login():
        return redirect_to_soc_login()

    if require_bank_login():
        return redirect(url_for("bank.bank_admin"))

    if request.method == "POST":
        username = request.form.get(
            "bank_username",
            "",
        ).strip()

        password = request.form.get(
            "bank_password",
            "",
        ).strip()

        expected_password = BANK_USERS.get(username)

        if (
            expected_password is not None
            and password == expected_password
        ):
            session["bank_authenticated"] = True
            session["bank_username"] = username

            flash(
                "Banking authentication successful.",
                "success",
            )

            return redirect(url_for("bank.bank_admin"))

        session.pop("bank_authenticated", None)
        session.pop("bank_username", None)

        flash(
            "Invalid banking credentials.",
            "error",
        )

    return render_template(
        "bank_login.html",
        bank_authenticated=False,
    )


@bank_bp.route("/bank/logout")
def bank_logout():
    if not require_login():
        return redirect_to_soc_login()

    session.pop("bank_authenticated", None)
    session.pop("bank_username", None)

    flash(
        "Banking session closed.",
        "success",
    )

    return redirect(url_for("bank.bank"))


@bank_bp.route(
    "/bank/search",
    methods=["GET", "POST"],
)
def bank_search():
    if not require_login():
        return redirect_to_soc_login()

    results = []
    query = ""
    injection_detected = False

    if request.method == "POST":
        query = request.form.get(
            "query",
            "",
        ).strip()

        if not query:
            flash(
                "Enter a transaction reference, account number "
                "or status.",
                "error",
            )

        elif looks_like_sql_injection(query):
            injection_detected = True

            # Simulate the information disclosure caused by
            # an injectable transaction-search query.
            results = (
                TRANSACTIONS
                + INTERNAL_DATABASE_RECORDS
            )

            flash(
                "The search returned records outside the normal "
                "transaction dataset.",
                "error",
            )

        else:
            lowered_query = query.lower()

            results = [
                transaction
                for transaction in TRANSACTIONS
                if lowered_query
                in transaction["id"].lower()
                or lowered_query
                in transaction["account"].lower()
                or lowered_query
                in transaction["status"].lower()
                or lowered_query
                in transaction["note"].lower()
            ]

    return render_template(
        "bank_search.html",
        results=results,
        query=query,
        injection_detected=injection_detected,
    )


@bank_bp.route(
    "/bank/upload",
    methods=["GET", "POST"],
)
def bank_upload():
    if not require_login():
        return redirect_to_soc_login()

    uploaded_file = None

    if request.method == "POST":
        file = request.files.get("file")

        if file and file.filename:
            uploaded_file = file.filename

            dangerous_extensions = (
                ".php",
                ".phtml",
                ".php5",
                ".jsp",
                ".jspx",
                ".aspx",
            )

            if uploaded_file.lower().endswith(
                dangerous_extensions
            ):
                flash(
                    "The upload filter generated a security alert.",
                    "error",
                )
            else:
                flash(
                    "File submitted for simulated review.",
                    "success",
                )

    return render_template(
        "bank_upload.html",
        uploaded_file=uploaded_file,
    )


@bank_bp.route("/bank/admin")
def bank_admin():
    if not require_login():
        return redirect_to_soc_login()

    if not require_bank_login():
        return redirect_to_bank_login()

    return render_template(
        "bank_admin.html",
        bank_username=session.get("bank_username"),
    )


@bank_bp.route("/bank/backup")
def bank_backup():
    if not require_login():
        return redirect_to_soc_login()

    if not require_bank_login():
        return redirect_to_bank_login()

    return render_template("bank_backup.html")


@bank_bp.route("/bank/uploads")
def bank_uploads():
    if not require_login():
        return redirect_to_soc_login()

    if not require_bank_login():
        return redirect_to_bank_login()

    return render_template("bank_uploads.html")


@bank_bp.route("/bank/uploads/shell.php")
def bank_shell():
    if not require_login():
        return redirect_to_soc_login()

    if not require_bank_login():
        return redirect_to_bank_login()

    return render_template("bank_shell.html")
