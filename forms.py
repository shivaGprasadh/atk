from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, URL, ValidationError
import re

class ScanForm(FlaskForm):
    """Form for submitting a new scan"""
    target_url = StringField('Target URL', validators=[DataRequired()])
    submit = SubmitField('Start Scan')
    
    def validate_target_url(self, field):
        """Validate the target URL format"""
        # Check if input is a domain, URL, or IP address
        url_pattern = re.compile(
            r'^(https?:\/\/)?' +  # http:// or https:// (optional)
            r'(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*' +  # domain segments
            r'([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])' +  # final domain segment
            r'(:\d+)?' +  # port (optional)
            r'(\/[-a-zA-Z0-9@:%_\+.~#?&//=]*)?' +  # path (optional)
            r'$'
        )
        
        ip_pattern = re.compile(
            r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'  # IPv4 pattern
        )
        
        url = field.data.strip()
        
        # If it's not a valid URL format or IP, raise error
        if not url_pattern.match(url) and not ip_pattern.match(url):
            raise ValidationError('Please enter a valid URL, domain name, or IP address')
        
        # If it's an IP address, check if it's valid
        if ip_pattern.match(url):
            octets = url.split('.')
            for octet in octets:
                if int(octet) > 255:
                    raise ValidationError('Invalid IP address')
        
        # If URL doesn't start with http:// or https://, prepend http://
        if not url.startswith(('http://', 'https://')):
            field.data = 'http://' + url
