FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir \
    beautifulsoup4==4.12.2 \
    chardet==5.1.0 \
    dnspython==2.4.1 \
    email-validator==2.0.0 \
    flask==2.3.3 \
    flask-login==0.6.3 \
    flask-sqlalchemy==3.1.1 \
    flask-wtf==1.2.1 \
    gunicorn==23.0.0 \
    psycopg2-binary==2.9.7 \
    pymupdf==1.23.5 \
    python-nmap==0.7.1 \
    python-whois==0.8.0 \
    reportlab==4.0.5 \
    requests==2.31.0 \
    scrapy==2.11.0 \
    sqlalchemy==2.0.21 \
    trafilatura==1.6.1 \
    werkzeug==2.3.7 \
    wtforms==3.0.1

# Copy application code
COPY . .

# Expose the port
EXPOSE 5000

# Run the application
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "main:app"]