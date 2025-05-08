import logging
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import json
from scrapy.crawler import CrawlerProcess
from scrapy.spiders import CrawlSpider, Rule
from scrapy.linkextractors import LinkExtractor
from scrapy import signals
from scrapy.signalmanager import dispatcher
import tempfile
import os

def crawl_website(url, max_pages=20):
    """
    Crawl a website using Scrapy
    
    Args:
        url (str): The URL to crawl
        max_pages (int): Maximum number of pages to crawl
        
    Returns:
        list: List of crawled URLs with status codes and content types
    """
    visited_urls = []
    
    class WebsiteCrawler(CrawlSpider):
        name = 'website_crawler'
        
        def __init__(self, *args, **kwargs):
            super(WebsiteCrawler, self).__init__(*args, **kwargs)
            self.start_urls = [kwargs.get('start_url')]
            parsed_url = urlparse(self.start_urls[0])
            self.allowed_domains = [parsed_url.netloc]
            self.pages_visited = 0
            self.max_pages = kwargs.get('max_pages', 20)
        
        rules = (
            Rule(LinkExtractor(), callback='parse_item', follow=True),
        )
        
        def parse_item(self, response):
            if self.pages_visited >= self.max_pages:
                return
            
            self.pages_visited += 1
            
            # Store visited URL info
            visited_urls.append({
                'url': response.url,
                'status_code': response.status,
                'content_type': response.headers.get('Content-Type', b'').decode('utf-8', errors='ignore')
            })
    
    try:
        # Create a temporary file for Scrapy logs
        temp_log = tempfile.NamedTemporaryFile(delete=False)
        temp_log.close()
        
        # Configure Scrapy settings
        process = CrawlerProcess(settings={
            'USER_AGENT': 'Attack Surface Scanner Bot (security research)',
            'ROBOTSTXT_OBEY': True,
            'CONCURRENT_REQUESTS': 4,
            'DOWNLOAD_DELAY': 1,
            'LOG_LEVEL': 'ERROR',
            'LOG_FILE': temp_log.name,
            'COOKIES_ENABLED': True,
            'TELNETCONSOLE_ENABLED': False
        })
        
        # Add the spider to the process
        process.crawl(WebsiteCrawler, start_url=url, max_pages=max_pages)
        
        # Run the crawler
        process.start()
        
        # Clean up temporary log file
        os.unlink(temp_log.name)
    
    except Exception as e:
        logging.error(f"Error during crawling: {str(e)}")
        
        # If Scrapy fails, fall back to a simpler crawler
        try:
            fallback_crawl(url, max_pages, visited_urls)
        except Exception as fallback_error:
            logging.error(f"Fallback crawler error: {str(fallback_error)}")
    
    return visited_urls

def fallback_crawl(url, max_pages, visited_urls):
    """
    Fallback crawler if Scrapy fails
    
    Args:
        url (str): The URL to crawl
        max_pages (int): Maximum number of pages to crawl
        visited_urls (list): List to store visited URLs
    """
    try:
        # Set to keep track of visited URLs
        visited = set()
        to_visit = [url]
        base_domain = urlparse(url).netloc
        
        headers = {'User-Agent': 'Attack Surface Scanner Bot (security research)'}
        
        while to_visit and len(visited) < max_pages:
            current_url = to_visit.pop(0)
            
            if current_url in visited:
                continue
            
            try:
                response = requests.get(current_url, headers=headers, timeout=10, verify=False)
                visited.add(current_url)
                
                # Store visited URL info
                visited_urls.append({
                    'url': current_url,
                    'status_code': response.status_code,
                    'content_type': response.headers.get('Content-Type', '').split(';')[0]
                })
                
                # Only parse HTML content for links
                if 'text/html' in response.headers.get('Content-Type', ''):
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Extract links
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        absolute_url = urljoin(current_url, href)
                        
                        # Only follow links to the same domain
                        if urlparse(absolute_url).netloc == base_domain and absolute_url not in visited:
                            to_visit.append(absolute_url)
            
            except requests.exceptions.RequestException as e:
                logging.error(f"Request error for {current_url}: {str(e)}")
            except Exception as e:
                logging.error(f"Error processing {current_url}: {str(e)}")
    
    except Exception as e:
        logging.error(f"Error in fallback crawler: {str(e)}")
