
import logging
from app import app, db
from sqlalchemy import text

logging.basicConfig(level=logging.INFO)

def add_cors_findings_column():
    """Add cors_findings column to http_scans table"""
    with app.app_context():
        try:
            # Check if column exists
            db.session.execute(text('PRAGMA table_info(http_scans)'))
            columns = db.session.execute(text('SELECT * FROM pragma_table_info("http_scans")'))
            column_names = [column[1] for column in columns]
            
            if 'cors_findings' not in column_names:
                db.session.execute(text('ALTER TABLE http_scans ADD COLUMN cors_findings TEXT'))
                db.session.commit()
                logging.info("Successfully added cors_findings column to http_scans table")
            else:
                logging.info("cors_findings column already exists")
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error adding cors_findings column: {str(e)}")
            raise

if __name__ == "__main__":
    add_cors_findings_column()
