import logging
import os
from logging.handlers import RotatingFileHandler

from flask import (
    Flask,
    render_template,
    session,
)

from config import Config
from database import init_db
from investigation_loader import (
    load_all_investigations,
)
from level_config import (
    get_all_cases,
    get_level_cases,
)
from models import (
    create_default_users,
    get_progress,
)

from routes.auth import auth_bp
from routes.bank import bank_bp
from routes.dashboard import dashboard_bp
from routes.evidence import evidence_bp
from routes.flags import flags_bp
from routes.investigations import investigations_bp
from soc_features import (
    initialise_soc_features,
    soc_features,
)


def configure_logging(app):
    handler = RotatingFileHandler(
        app.config["LOG_FILE"],
        maxBytes=1_000_000,
        backupCount=3,
    )

    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)s %(message)s"
        )
    )

    handler.setLevel(logging.INFO)

    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)


def create_app(test_config=None):
    app = Flask(__name__)

    app.config.from_object(Config)

    if test_config:
        app.config.update(test_config)

    if not app.config.get("SECRET_KEY"):
        raise RuntimeError(
            "BLACK_FALCON_SECRET_KEY is not configured."
        )

    app.config.setdefault(
        "EVIDENCE_FOLDER",
        app.config["EVIDENCE_DIR"],
    )

    init_db(app)
    configure_logging(app)

    with app.app_context():
        create_default_users()
        initialise_soc_features()

    @app.context_processor
    def inject_navigation_context():
        if not session.get("logged_in"):
            return {
                "nav_investigations": [],
                "progress_map": {},
                "current_user": None,
            }

        username = session.get("username")
        progress_map = get_progress(username)
        selected_level = session.get(
            "selected_level",
            "beginner",
        )
        level_cases = set(
            get_level_cases(selected_level)
        )
        all_cases = get_all_cases()
        soc_mission_complete = all(
            progress_map.get(
                case_id,
                {},
            ).get(
                "completed",
                False,
            )
            for case_id in all_cases
        )

        return {
            "nav_investigations":
                [
                    investigation
                    for investigation in load_all_investigations()
                    if investigation.get("id")
                    in level_cases
                ],
            "progress_map":
                progress_map,
            "soc_mission_complete":
                soc_mission_complete,
            "selected_level":
                selected_level,
            "current_user":
                username,
        }

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(investigations_bp)
    app.register_blueprint(flags_bp)
    app.register_blueprint(evidence_bp)
    app.register_blueprint(bank_bp)
    app.register_blueprint(soc_features)

    @app.errorhandler(404)
    def not_found(error):
        del error

        return render_template(
            "error.html",
            code=404,
            message="Page not found.",
        ), 404

    @app.errorhandler(403)
    def forbidden(error):
        del error

        return render_template(
            "error.html",
            code=403,
            message="Access denied.",
        ), 403

    @app.errorhandler(413)
    def file_too_large(error):
        del error

        return render_template(
            "error.html",
            code=413,
            message="Uploaded file is too large.",
        ), 413

    return app


if __name__ == "__main__":
    app = create_app()

    debug_enabled = (
        os.environ.get("FLASK_DEBUG", "0") == "1"
    )

    app.run(
        host="0.0.0.0",
        port=5555,
        debug=debug_enabled,
    )
