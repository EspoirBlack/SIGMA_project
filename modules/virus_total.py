
# VirusTotal API Integration Module
# Checks IP addresses against VirusTotal for threat intelligence

import requests
import time
import logging
from datetime import datetime

class VirusTotalChecker:
    def __init__(self, api_key):
        # Initialize VirusTotal checker

        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": api_key,
            "Accept": "application/json"
        }
        self.cache = {}  # Cache results to avoid repeated API calls
        self.request_timestamps = []  # Track request times for rate limiting
        logging.basicConfig(level=logging.INFO)
        
    def _check_rate_limit(self):
        # Check and enforce rate limit (4 requests per minute)

        if not self.api_key or self.api_key == '':
            return False
            
        current_time = time.time()
        # Remove timestamps older than 60 seconds
        self.request_timestamps = [t for t in self.request_timestamps if current_time - t < 60]
        
        if len(self.request_timestamps) >= 4:
            oldest = self.request_timestamps[0]
            wait_time = 60 - (current_time - oldest)
            if wait_time > 0:
                logging.info(f"Rate limit reached, waiting {wait_time:.1f} seconds")
                time.sleep(wait_time)
                return self._check_rate_limit()
        
        return True
    
    def _add_request_timestamp(self):
        #Record a request timestamp for rate limiting
        self.request_timestamps.append(time.time())
    
    def check_ip(self, ip_address):
        # Check an IP address against VirusTotal and Returns analysis results
        if not self.api_key or self.api_key == '':
            return {
                'success': False,
                'error': 'No API key configured',
                'message': 'Please add your VirusTotal API key to config.py'
            }
        
        # Check cache first
        cache_key = f"ip_{ip_address}"
        if cache_key in self.cache:
            cache_time = self.cache[cache_key].get('cached_at', 0)
            # Cache for 1 hour
            if time.time() - cache_time < 3600:
                logging.info(f"Returning cached result for IP: {ip_address}")
                return self.cache[cache_key].get('data')
        
        try:
            # Rate limiting
            self._check_rate_limit()
            
            # Make API request
            url = f"{self.base_url}/ip_addresses/{ip_address}"
            response = requests.get(url, headers=self.headers, timeout=10)
            self._add_request_timestamp()
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})
                
                result = {
                    'success': True,
                    'ip': ip_address,
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0),
                    'total': sum(stats.values()),
                    'reputation': attributes.get('reputation', 0),
                    'country': attributes.get('country', 'Unknown'),
                    'as_owner': attributes.get('as_owner', 'Unknown'),
                    'network': attributes.get('network', 'Unknown'),
                    'whois': attributes.get('whois', 'Not available')[:200] if attributes.get('whois') else 'Not available'
                }
                
                # Determine verdict
                if result['malicious'] > 0:
                    result['verdict'] = 'MALICIOUS'
                    result['color'] = 'danger'
                    result['icon'] = 'fa-skull-crosswalk'
                    result['message'] = f'This IP has been flagged as malicious by {result["malicious"]} security vendors'
                elif result['suspicious'] > 0:
                    result['verdict'] = 'SUSPICIOUS'
                    result['color'] = 'warning'
                    result['icon'] = 'fa-exclamation-triangle'
                    result['message'] = f'This IP has been flagged as suspicious by {result["suspicious"]} security vendors'
                else:
                    result['verdict'] = 'CLEAN'
                    result['color'] = 'success'
                    result['icon'] = 'fa-check-circle'
                    result['message'] = 'No security vendors flagged this IP as malicious'
                
                # Cache result
                self.cache[cache_key] = {
                    'data': result,
                    'cached_at': time.time()
                }
                
                return result
                
            elif response.status_code == 429:
                return {
                    'success': False,
                    'error': 'Rate limit exceeded',
                    'message': 'Please wait before making more requests'
                }
            elif response.status_code == 404:
                return {
                    'success': False,
                    'ip': ip_address,
                    'error': 'Not Found',
                    'message': 'IP address not found in VirusTotal database'
                }
            else:
                return {
                    'success': False,
                    'error': f'API returned {response.status_code}',
                    'message': response.text[:200]
                }
                
        except requests.exceptions.Timeout:
            return {
                'success': False,
                'error': 'Request timeout',
                'message': 'VirusTotal API did not respond in time'
            }
        except requests.exceptions.ConnectionError:
            return {
                'success': False,
                'error': 'Connection error',
                'message': 'Could not connect to VirusTotal API'
            }
        except Exception as e:
            logging.error(f"VirusTotal API error: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def clear_cache(self):
        """Clear the result cache"""
        self.cache = {}
        logging.info("VirusTotal cache cleared")
    
    def get_cache_stats(self):
        """Get cache statistics"""
        return {
            'cache_size': len(self.cache),
            'cached_items': list(self.cache.keys())[:10]
        }