# Attack Surface Management Tool

A comprehensive web-based tool for security scanning and vulnerability detection, focusing on precise network and web infrastructure analysis.

## Features

- **IP Information**: Gather IP address details, geolocation, and ASN information
- **DNS Analysis**: Analyze DNS records and DNSSEC implementation
- **SSL Certificate Analysis**: Check SSL certificate validity, expiration, and configurations
- **HTTP Header Security**: Review HTTP security headers and recommendations
- **Port Scanning**: Discover open ports and services
- **CORS Security Analysis**: Check for Cross-Origin Resource Sharing misconfigurations
- **Cookie Security**: Analyze cookie security settings and flags
- **Information Disclosure Detection**: Find potential credentials, PII, or internal information
- **Web Crawling**: Discover and analyze linked pages on the target site
- **Comprehensive Reporting**: Export findings in PDF, JSON, and CSV formats

## Technical Architecture

This application is built with:

- **Backend**: Python 3.11+ with Flask framework
- **Database**: PostgreSQL for persistent storage
- **Interface**: Bootstrap-based responsive UI
- **Visualization**: Chart.js for data visualization
- **PDF Generation**: ReportLab for PDF report exports

## Prerequisites

- Python 3.11 or higher
- PostgreSQL database
- Python development headers (for some dependencies)
- Network access for security scanning

## Required Python Packages

- flask
- flask-login
- flask-sqlalchemy
- flask-wtf
- gunicorn
- psycopg2-binary
- python-nmap
- python-whois
- requests
- beautifulsoup4
- scrapy
- trafilatura
- reportlab
- pymupdf
- dnspython
- werkzeug

## Database Setup

The application requires a PostgreSQL database. Set up the database connection using environment variables:

```
DATABASE_URL=postgresql://username:password@hostname:port/dbname
```

The application will automatically create the necessary tables on startup if they don't exist.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/shivaGprasadh/attack-surface-management.git
   cd attack-surface-management
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Configure the database URL in your environment:
   ```bash
   export DATABASE_URL=postgresql://username:password@hostname:port/dbname
   # On Windows: set DATABASE_URL=postgresql://username:password@hostname:port/dbname
   ```

5. Set a session secret:
   ```bash
   export SESSION_SECRET=your-secure-random-string
   # On Windows: set SESSION_SECRET=your-secure-random-string
   ```

## Running the Application

### Development Mode

```bash
python main.py
```

### Production Mode (with Gunicorn)

```bash
gunicorn --bind 0.0.0.0:5002 --workers 4 main:app
```

## Deployment Options

### Docker Deployment

1. Build the Docker image:
   ```bash
   docker build -t attack-surface-management .
   ```

2. Run the container:
   ```bash
   docker run -d -p 5002:5002 \
     -e DATABASE_URL=postgresql://username:password@hostname:port/dbname \
     -e SESSION_SECRET=your-secure-random-string \
     --name attack-surface attack-surface-management
   ```

### Cloud Deployment

The application can be deployed to various cloud platforms that support Python applications:

1. **Heroku**:
   - Add a `Procfile` with: `web: gunicorn main:app`
   - Deploy using the Heroku CLI or GitHub integration

2. **AWS Elastic Beanstalk**:
   - Create an application and environment
   - Configure environment variables for database connection
   - Deploy using the EB CLI or AWS console

3. **Google Cloud Run**:
   - Build and push a Docker image to Container Registry
   - Deploy using the GCP console or `gcloud` CLI

4. **Azure App Service**:
   - Create an App Service with Python 3.11
   - Configure environment variables
   - Deploy using VS Code extension, Azure CLI, or GitHub integration

## Database Migrations

When upgrading the application to a new version, database migrations might be required. The application will automatically update the schema on startup, but it's recommended to back up your data before upgrading.

## Security Considerations

- Run the application behind a reverse proxy like Nginx or Apache
- Enable HTTPS to protect sensitive data
- Consider IP restrictions for access to the application
- Use strong, randomly generated passwords for the database
- Regularly update dependencies to address security vulnerabilities

## License

[MIT License](LICENSE)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
