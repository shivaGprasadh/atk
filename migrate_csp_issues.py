import logging
from app import app, db
from sqlalchemy import Column, Text, text

logging.basicConfig(level=logging.INFO)

def add_csp_issues_column():
    """Add csp_issues column to http_scans table"""
    with app.app_context():
        try:
            # Create the new column using text() function
            db.session.execute(text('ALTER TABLE http_scans ADD COLUMN IF NOT EXISTS csp_issues TEXT'))
            db.session.commit()
            logging.info("Successfully added csp_issues column to http_scans table")
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error adding csp_issues column: {str(e)}")
            raise

if __name__ == "__main__":
    add_csp_issues_column()