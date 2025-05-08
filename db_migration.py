import logging
from app import app, db
from sqlalchemy import text

logging.basicConfig(level=logging.INFO)

def add_cors_findings_column():
    """Add cors_findings column to http_scans table"""
    with app.app_context():
        try:
            # Check if the column exists using PostgreSQL
            result = db.session.execute(text("SELECT column_name FROM information_schema.columns WHERE table_name='http_scans' AND column_name='cors_findings';"))
            exists = result.fetchone() is not None
            
            if not exists:
                db.session.execute(text('ALTER TABLE http_scans ADD COLUMN cors_findings TEXT;'))
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
