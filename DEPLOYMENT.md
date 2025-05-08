# Deployment Guide for Attack Surface Management Tool

This guide provides detailed instructions for setting up and deploying the Attack Surface Management application in different environments.

## Prerequisites

- Python 3.11 or higher
- PostgreSQL database server
- Access to install Python packages

## Required Packages

Install the following Python packages:

```bash
pip install beautifulsoup4==4.12.2
pip install chardet==5.1.0
pip install dnspython==2.4.1
pip install email-validator==2.0.0
pip install flask==2.3.3
pip install flask-login==0.6.3
pip install flask-sqlalchemy==3.1.1
pip install flask-wtf==1.2.1
pip install gunicorn==23.0.0
pip install psycopg2-binary==2.9.7
pip install pymupdf==1.23.5
pip install python-nmap==0.7.1
pip install python-whois==0.8.0
pip install reportlab==4.0.5
pip install requests==2.31.0
pip install scrapy==2.11.0
pip install sqlalchemy==2.0.21
pip install trafilatura==1.6.1
pip install werkzeug==2.3.7
pip install wtforms==3.0.1
```

## Database Setup

### PostgreSQL Installation

1. **Ubuntu/Debian**:
   ```bash
   sudo apt update
   sudo apt install postgresql postgresql-contrib
   ```

2. **Red Hat/CentOS/Fedora**:
   ```bash
   sudo dnf install postgresql-server postgresql-contrib
   sudo postgresql-setup --initdb
   sudo systemctl enable postgresql
   sudo systemctl start postgresql
   ```

3. **macOS** (using Homebrew):
   ```bash
   brew install postgresql
   brew services start postgresql
   ```

4. **Windows**:
   - Download installer from: https://www.postgresql.org/download/windows/
   - Follow the installation wizard instructions

### Creating a Database

1. Log in to PostgreSQL:
   ```bash
   sudo -u postgres psql
   ```
   or
   ```bash
    psql -U $(whoami) -d postgres
   ```


3. Create a database user:
   ```sql
   CREATE USER asmt_user WITH PASSWORD 'your_secure_password';
   ```

4. Create a database:
   ```sql
   CREATE DATABASE asmt_db OWNER asmt_user;
   ```

5. Grant privileges:
   ```sql
   GRANT ALL PRIVILEGES ON DATABASE asmt_db TO asmt_user;
   ```

6. Exit PostgreSQL:
   ```sql
   \q
   ```

## Environment Configuration

Create a `.env` file in the project root with the following contents:

```
DATABASE_URL=postgresql://asmt_user:your_secure_password@localhost:5432/asmt_db
SESSION_SECRET=your_secure_random_string
```

Replace these values with your actual database credentials and a secure random string for session encryption.

## Deployment Options

### Local Development

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/attack-surface-management.git
   cd attack-surface-management
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install the required packages (as listed above)

4. Set up environment variables:
   ```bash
   export DATABASE_URL=postgresql://asmt_user:your_secure_password@localhost:5432/asmt_db
   export SESSION_SECRET=your_secure_random_string
   ```

5. Run the development server:
   ```bash
   python main.py
   ```

### Production Deployment

#### Using Gunicorn

1. Install Gunicorn:
   ```bash
   pip install gunicorn
   ```

2. Run with Gunicorn:
   ```bash
   gunicorn --bind 0.0.0.0:5000 --workers 4 main:app
   ```

#### Using a Systemd Service (Linux)

1. Create a systemd service file:
   ```bash
   sudo nano /etc/systemd/system/asmt.service
   ```

2. Add the following content:
   ```
   [Unit]
   Description=Attack Surface Management Tool
   After=network.target postgresql.service

   [Service]
   User=your_user
   WorkingDirectory=/path/to/attack-surface-management
   Environment="DATABASE_URL=postgresql://asmt_user:your_secure_password@localhost:5432/asmt_db"
   Environment="SESSION_SECRET=your_secure_random_string"
   ExecStart=/path/to/venv/bin/gunicorn --bind 0.0.0.0:5000 --workers 4 main:app
   Restart=always

   [Install]
   WantedBy=multi-user.target
   ```

3. Enable and start the service:
   ```bash
   sudo systemctl enable asmt
   sudo systemctl start asmt
   ```

#### Reverse Proxy with Nginx

1. Install Nginx:
   ```bash
   sudo apt install nginx  # Ubuntu/Debian
   ```

2. Create an Nginx configuration:
   ```bash
   sudo nano /etc/nginx/sites-available/asmt
   ```

3. Add the following configuration:
   ```
   server {
       listen 80;
       server_name your_domain.com;

       location / {
           proxy_pass http://127.0.0.1:5000;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
       }
   }
   ```

4. Create a symbolic link and restart Nginx:
   ```bash
   sudo ln -s /etc/nginx/sites-available/asmt /etc/nginx/sites-enabled/
   sudo systemctl restart nginx
   ```

5. Set up SSL with Let's Encrypt:
   ```bash
   sudo apt install certbot python3-certbot-nginx
   sudo certbot --nginx -d your_domain.com
   ```

### Docker Deployment

1. Create a Dockerfile in your project root:

```Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose the port
EXPOSE 5000

# Run the application
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "main:app"]
```

2. Create a docker-compose.yml file:

```yaml
version: '3'

services:
  app:
    build: .
    ports:
      - "5000:5000"
    environment:
      - DATABASE_URL=postgresql://asmt_user:your_secure_password@db:5432/asmt_db
      - SESSION_SECRET=your_secure_random_string
    depends_on:
      - db
    restart: always

  db:
    image: postgres:14
    environment:
      - POSTGRES_USER=asmt_user
      - POSTGRES_PASSWORD=your_secure_password
      - POSTGRES_DB=asmt_db
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: always

volumes:
  postgres_data:
```

3. Build and run with Docker Compose:
   ```bash
   docker-compose up -d
   ```

## Cloud Deployment

### Heroku

1. Install the Heroku CLI and log in:
   ```bash
   npm install -g heroku
   heroku login
   ```

2. Create a new Heroku app:
   ```bash
   heroku create your-app-name
   ```

3. Add PostgreSQL add-on:
   ```bash
   heroku addons:create heroku-postgresql:hobby-dev
   ```

4. Set environment variables:
   ```bash
   heroku config:set SESSION_SECRET=your_secure_random_string
   ```

5. Create a Procfile in your project root:
   ```
   web: gunicorn main:app
   ```

6. Deploy to Heroku:
   ```bash
   git push heroku main
   ```

### AWS Elastic Beanstalk

1. Install the EB CLI:
   ```bash
   pip install awsebcli
   ```

2. Initialize your EB application:
   ```bash
   eb init -p python-3.11 your-app-name
   ```

3. Create a `.ebextensions/01_packages.config` file:
   ```yaml
   packages:
     yum:
       postgresql-devel: []
       nmap: []
   ```

4. Create a `requirements.txt` file with all dependencies

5. Create the environment:
   ```bash
   eb create your-environment-name
   ```

6. Set environment variables:
   ```bash
   eb setenv DATABASE_URL=postgresql://user:password@your-rds-endpoint:5432/dbname SESSION_SECRET=your_secure_random_string
   ```

7. Deploy:
   ```bash
   eb deploy
   ```

## Troubleshooting

### Database Connection Issues

1. Verify PostgreSQL is running:
   ```bash
   sudo systemctl status postgresql
   ```

2. Check database credentials:
   ```bash
   psql -U asmt_user -h localhost -d asmt_db
   ```

3. Verify firewall settings:
   ```bash
   sudo ufw status
   ```

### Application Errors

1. Check application logs:
   ```bash
   journalctl -u asmt.service  # For systemd service
   heroku logs --tail          # For Heroku
   ```

2. Verify environment variables:
   ```bash
   printenv | grep DATABASE_URL
   printenv | grep SESSION_SECRET
   ```

## Security Recommendations

1. Always use HTTPS in production
2. Keep all packages updated regularly
3. Use strong, unique passwords for database accounts
4. Consider setting up IP restrictions for administrative access
5. Implement a firewall on your server
6. Set up automated backups for your database
7. Regularly review application logs for suspicious activity
