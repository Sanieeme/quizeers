"""
Entry point for running the app locally: `python3 run.py`.

This file's only job is to create the app and run the dev server -- all
actual application logic lives in the quizeers/ package.
"""
from quizeers import create_app
from quizeers.extensions import db

app = create_app()

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
