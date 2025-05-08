
import builtwith
import logging

def analyze_tech_stack(url):
    """
    Analyze the technology stack of a website using BuiltWith
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        dict: Technology categories and their corresponding technologies
    """
    try:
        tech_info = builtwith.parse(url)
        
        # Format the results
        formatted_results = {}
        for category, technologies in tech_info.items():
            # Clean up category name
            clean_category = category.replace('-', ' ').title()
            # Remove duplicates and sort technologies
            formatted_results[clean_category] = sorted(set(technologies))
            
        return formatted_results
        
    except Exception as e:
        logging.error(f"Error analyzing tech stack: {str(e)}")
        return {}
