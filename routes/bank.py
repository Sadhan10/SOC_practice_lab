import hashlib
import hmac

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


BANK_ADMIN_DISCOVERY_KEY = (
    "bank_admin_discovered"
)

OBSERVED_SQLI_PAYLOAD = (
    "' OR 1=1 --"
)


BANK_PASSWORD_ITERATIONS = 310_000
BANK_USERS = {
    "admin": {
        "salt": "black-falcon-bank-admin-v1",
        "password_hash": (
            "228127b9df6e0c174ea6c87b957ebcee"
            "3fb29e7ccdafc130b31d3dab331db6b2"
        ),
    },
    "customer": {
        "salt": "black-falcon-bank-customer-v1",
        "password_hash": (
            "3f61678208e2c932ca1513fe81448d0e"
            "f776ca0fce6b1a089a379b83a813cae9"
        ),
    },
}


def verify_bank_password(
    username,
    submitted_password,
):
    """
    Verify a simulated banking credential without storing
    the plaintext password in the application source.
    """
    account = BANK_USERS.get(username)
    if not account:
        return False

    calculated_hash = hashlib.pbkdf2_hmac(
        "sha256",
        submitted_password.encode("utf-8"),
        account["salt"].encode("utf-8"),
        BANK_PASSWORD_ITERATIONS,
    ).hex()
    return hmac.compare_digest(
        calculated_hash,
        account["password_hash"],
    )


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


def require_admin_discovery():
    """
    Return True after the analyst has reproduced the
    transaction-search anomaly that exposes the hidden
    administration path.
    """

    return (
        session.get(
            BANK_ADMIN_DISCOVERY_KEY
        )
        is True
    )


def looks_like_sql_injection(value):
    """
    Reproduce the SQL injection payload observed in the
    Black Falcon Bank incident evidence.

    This training application does not execute SQL.
    It only simulates the behaviour recorded in the
    investigation evidence.
    """

    normalized = " ".join(
        value.strip().split()
    )

    return (
        normalized.casefold()
        == OBSERVED_SQLI_PAYLOAD.casefold()
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


def redirect_to_bank_search():
    flash(
        "The restricted banking resource has not yet "
        "been identified. Review the transaction-search "
        "behaviour first.",
        "error",
    )

    return redirect(
        url_for("bank.bank_search")
    )


@bank_bp.route("/bank")
def bank():
    if not require_login():
        return redirect_to_soc_login()

    return render_template(
        "bank.html",
        bank_authenticated=require_bank_login(),
        bank_username=session.get("bank_username"),
        admin_discovered=require_admin_discovery(),
    )


@bank_bp.route(
    "/bank/login",
    methods=["GET", "POST"],
)
def bank_login():
    if not require_login():
        return redirect_to_soc_login()

    if require_bank_login():
        return redirect(url_for("bank.bank"))

    if request.method == "POST":
        username = request.form.get(
            "bank_username",
            "",
        ).strip()

        password = request.form.get(
            "bank_password",
            "",
        ).strip()

        if verify_bank_password(
            username,
            password,
        ):
            session["bank_authenticated"] = True
            session["bank_username"] = username

            flash(
                "Banking authentication successful. "
                "Continue reviewing the banking application "
                "to reconstruct the intrusion.",
                "success",
            )

            return redirect(url_for("bank.bank"))

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
            session[BANK_ADMIN_DISCOVERY_KEY] = True

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

    if not require_admin_discovery():
        return redirect_to_bank_search()

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

    if not require_admin_discovery():
        return redirect_to_bank_search()

    return render_template("bank_backup.html")


@bank_bp.route("/bank/uploads")
def bank_uploads():
    if not require_login():
        return redirect_to_soc_login()

    if not require_bank_login():
        return redirect_to_bank_login()

    if not require_admin_discovery():
        return redirect_to_bank_search()

    return render_template("bank_uploads.html")


@bank_bp.route("/bank/uploads/shell.php")
def bank_shell():
    if not require_login():
        return redirect_to_soc_login()

    if not require_bank_login():
        return redirect_to_bank_login()

    if not require_admin_discovery():
        return redirect_to_bank_search()

    return render_template("bank_shell.html")
