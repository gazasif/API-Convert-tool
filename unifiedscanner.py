#!/usr/bin/env python3
"""
User-Friendly Unified API Scanner
Guided interface for scanning API files
"""

import json
import re
import os
import sys
import csv
import subprocess
from typing import Dict, List, Any, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qs
from pathlib import Path

class DependencyInstaller:
    """Handles automatic installation of required dependencies"""
    
    REQUIRED_PACKAGES = {
        'pyyaml': 'yaml',
        'pdfplumber': 'pdfplumber',
        'pymupdf': 'fitz'
    }
    
    @staticmethod
    def install_dependencies():
        """Install required packages if not available"""
        print("🔍 Checking dependencies...")
        missing_packages = []
        
        for package, import_name in DependencyInstaller.REQUIRED_PACKAGES.items():
            try:
                __import__(import_name)
                print(f"✓ {package} is already installed")
            except ImportError:
                missing_packages.append(package)
                print(f"✗ {package} is missing")
        
        if missing_packages:
            print("\n📦 Installing missing dependencies...")
            for package in missing_packages:
                try:
                    print(f"Installing {package}...")
                    subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                    print(f"✓ Successfully installed {package}")
                except subprocess.CalledProcessError:
                    print(f"✗ Failed to install {package}")
                    return False
        print("✓ All dependencies are ready!\n")
        return True

class UnifiedAPIScanner:
    def __init__(self):
        self.excel_results = []
        self.column_headers = [
            "Sl. No", "Domain", "Domain Route Required", "Base App", 
            "Service Type", "Service URL", "Service Base (HTTP/API)", 
            "API Information", "Method", "IP Address : Port (external)", 
            "SSL/TLS Version"
        ]
        
        self.openapi_spec = {
            "openapi": "3.0.0",
            "info": {
                "title": "API Documentation",
                "version": "1.0.0",
                "description": "Generated from API scan"
            },
            "servers": [{"url": "http://localhost:3000", "description": "Development server"}],
            "paths": {},
            "components": {
                "schemas": {},
                "securitySchemes": {
                    "bearerAuth": {
                        "type": "http",
                        "scheme": "bearer",
                        "bearerFormat": "JWT"
                    }
                }
            }
        }
        
        self.seen_endpoints: Set[str] = set()
        self.variables = {}
    
    def process_postman_collection(self, file_path: str) -> bool:
        """Process Postman collection"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                postman_data = json.load(f)
            
            self._extract_info(postman_data)
            self._extract_variables(postman_data)
            
            if 'item' in postman_data:
                self._process_postman_items_for_excel(postman_data['item'], 1)
                self._process_postman_items_for_openapi(postman_data['item'])
            
            return True
        except Exception as e:
            raise Exception(f"Error processing Postman collection: {str(e)}")
    
    def _process_postman_items_for_openapi(self, items: List[Dict], parent_path: str = "") -> None:
        """Process Postman items for OpenAPI"""
        for item in items:
            if 'item' in item:
                folder_name = item.get('name', '')
                self._process_postman_items_for_openapi(item['item'], f"{parent_path}/{folder_name}")
            else:
                self._process_request_for_openapi(item, parent_path)
    
    def _process_request_for_openapi(self, request: Dict, parent_path: str) -> None:
        """Process a single request for OpenAPI"""
        try:
            name = request.get('name', 'Unnamed Request')
            method = request.get('request', {}).get('method', 'GET').lower()
            url_obj = request.get('request', {}).get('url', {})
            
            service_url, domain = self._extract_url_and_domain(url_obj)
            path = self._extract_path_from_url(service_url)
            path = self._convert_path_variables(path)
            path = self._remove_duplicate_query_params(path)
            
            # Create endpoint signature for duplicate check
            endpoint_signature = f"{method}_{path}"
            if endpoint_signature in self.seen_endpoints:
                return
            self.seen_endpoints.add(endpoint_signature)
            
            if path not in self.openapi_spec['paths']:
                self.openapi_spec['paths'][path] = {}
            
            method_obj = {
                "summary": name,
                "description": request.get('request', {}).get('description', ''),
                "responses": {
                    "200": {
                        "description": "Successful response",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object"
                                }
                            }
                        }
                    }
                }
            }
            
            # Process authentication
            auth = request.get('request', {}).get('auth', {})
            if auth and auth.get('type') == 'bearer':
                method_obj["security"] = [{"bearerAuth": []}]
            
            # Process request body
            body = request.get('request', {}).get('body', {})
            if body and body.get('mode'):
                method_obj["requestBody"] = self._process_request_body(body)
            
            # Process headers and parameters
            headers = request.get('request', {}).get('header', [])
            query_params = url_obj.get('query', []) if isinstance(url_obj, dict) else []
            
            parameters = self._process_parameters(headers, query_params)
            if parameters:
                method_obj["parameters"] = parameters
            
            self.openapi_spec['paths'][path][method] = method_obj
            
        except Exception as e:
            print(f"Warning: Failed to process request for OpenAPI: {str(e)}")
    
    def _process_request_body(self, body: Dict) -> Dict:
        """Process request body for OpenAPI"""
        body_mode = body.get('mode')
        body_content = {}
        
        if body_mode == 'raw':
            raw_body = body.get('raw', '')
            if raw_body:
                try:
                    json_body = json.loads(raw_body)
                    body_content = {
                        "content": {
                            "application/json": {
                                "schema": self._json_to_schema(json_body)
                            }
                        }
                    }
                except json.JSONDecodeError:
                    body_content = {
                        "content": {
                            "text/plain": {
                                "schema": {
                                    "type": "string",
                                    "example": raw_body
                                }
                            }
                        }
                    }
        
        return body_content
    
    def _process_parameters(self, headers: List[Dict], query_params: List[Dict]) -> List[Dict]:
        """Process parameters for OpenAPI"""
        parameters = []
        seen_params = set()
        
        for header in headers:
            if header.get('key') and not header.get('disabled', False):
                param_name = f"header:{header['key']}".lower()
                if param_name not in seen_params:
                    seen_params.add(param_name)
                    parameters.append({
                        "in": "header",
                        "name": header['key'],
                        "schema": {"type": "string", "example": header.get('value', '')},
                        "description": header.get('description', '')
                    })
        
        for param in query_params:
            if param.get('key'):
                param_name = f"query:{param['key']}".lower()
                if param_name not in seen_params:
                    seen_params.add(param_name)
                    parameters.append({
                        "in": "query",
                        "name": param['key'],
                        "schema": {"type": "string", "example": param.get('value', '')},
                        "description": param.get('description', '')
                    })
        
        return parameters
    
    def _json_to_schema(self, json_data: Any) -> Dict:
        """Convert JSON to OpenAPI schema"""
        if isinstance(json_data, dict):
            properties = {}
            required = []
            
            for key, value in json_data.items():
                properties[key] = self._json_to_schema(value)
                required.append(key)
            
            return {"type": "object", "properties": properties, "required": required}
        elif isinstance(json_data, list):
            if json_data:
                return {"type": "array", "items": self._json_to_schema(json_data[0])}
            else:
                return {"type": "array", "items": {}}
        elif isinstance(json_data, str):
            return {"type": "string", "example": json_data}
        elif isinstance(json_data, bool):
            return {"type": "boolean", "example": json_data}
        elif isinstance(json_data, int):
            return {"type": "integer", "example": json_data}
        elif isinstance(json_data, float):
            return {"type": "number", "example": json_data}
        else:
            return {"type": "string"}
    
    def _extract_path_from_url(self, url: str) -> str:
        """Extract path from URL"""
        try:
            if '://' in url:
                parsed = urlparse('https://' + url if not url.startswith(('http://', 'https://')) else url)
                path = parsed.path
                if parsed.query:
                    path += '?' + parsed.query
                return path
            return url
        except:
            return url
    
    def _convert_path_variables(self, path: str) -> str:
        """Convert variables to OpenAPI format"""
        return re.sub(r'{{([^}]+)}}', r'{\1}', path)
    
    def _remove_duplicate_query_params(self, path: str) -> str:
        """Remove duplicate query parameters"""
        if '?' not in path:
            return path
        
        base_path, query_string = path.split('?', 1)
        query_params = parse_qs(query_string)
        
        unique_params = {}
        for key, values in query_params.items():
            if values:
                unique_params[key] = values[0]
        
        if unique_params:
            new_query = '&'.join([f"{k}={v}" for k, v in unique_params.items()])
            return f"{base_path}?{new_query}"
        else:
            return base_path
    
    def process_raw_logs(self, file_path: str) -> bool:
        """Process raw logs"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                log_data = f.readlines()
            
            self._process_log_data_for_excel(log_data)
            self._process_log_data_for_openapi(log_data)
            
            return True
        except Exception as e:
            raise Exception(f"Error processing log file: {str(e)}")
    
    def _process_log_data_for_openapi(self, log_lines: List[str]) -> None:
        """Process raw log data for OpenAPI"""
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        method_pattern = r'(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+'
        
        for line in log_lines:
            urls = re.findall(url_pattern, line)
            methods = re.findall(method_pattern, line.upper())
            
            for url in urls:
                try:
                    method = methods[0].lower() if methods else "get"
                    path = self._extract_path_from_url(url)
                    path = self._convert_path_variables(path)
                    path = self._remove_duplicate_query_params(path)
                    
                    # Create endpoint signature for duplicate check
                    endpoint_signature = f"{method}_{path}"
                    if endpoint_signature in self.seen_endpoints:
                        continue
                    self.seen_endpoints.add(endpoint_signature)
                    
                    if path not in self.openapi_spec['paths']:
                        self.openapi_spec['paths'][path] = {}
                    
                    method_obj = {
                        "summary": f"Endpoint from logs - {path}",
                        "description": "Automatically generated from server logs",
                        "responses": {
                            "200": {
                                "description": "Successful response",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object"
                                        }
                                    }
                                }
                            }
                        }
                    }
                    
                    self.openapi_spec['paths'][path][method] = method_obj
                    
                except Exception as e:
                    continue
    
    def process_pdf_file(self, file_path: str) -> bool:
        """Process PDF file"""
        try:
            import fitz  # PyMuPDF
            with fitz.open(file_path) as pdf:
                text = ""
                for page in pdf:
                    text += page.get_text() + "\n"
            
            self._extract_apis_from_text(text)
            return True
        except Exception as e:
            raise Exception(f"Error processing PDF file: {str(e)}")
    
    def _extract_apis_from_text(self, text: str) -> None:
        """Extract APIs from text content"""
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        method_pattern = r'(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+'
        
        sl_no = len(self.excel_results) + 1
        
        urls = re.findall(url_pattern, text, re.IGNORECASE)
        for url in urls:
            try:
                method_match = re.search(method_pattern, text, re.IGNORECASE)
                method = method_match.group(1) if method_match else "GET"
                
                parsed = urlparse(url)
                domain = parsed.netloc or "example.com"
                
                endpoint_signature = f"{method}_{url}"
                if endpoint_signature in self.seen_endpoints:
                    continue
                self.seen_endpoints.add(endpoint_signature)
                
                service_type = self._determine_service_type(url)
                service_base = self._determine_service_base(url)
                
                result = {
                    "Sl. No": sl_no,
                    "Domain": domain,
                    "Domain Route Required": "Check if required",
                    "Base App": self._extract_base_app(domain),
                    "Service Type": service_type,
                    "Service URL": url,
                    "Service Base (HTTP/API)": service_base,
                    "API Information": self._get_api_information(service_base, method),
                    "Method": method,
                    "IP Address : Port (external)": "",
                    "SSL/TLS Version": ""
                }
                
                self.excel_results.append(result)
                sl_no += 1
                
                self._add_to_openapi(url, method, f"Endpoint from documentation - {url}")
                
            except Exception:
                continue
    
    def _add_to_openapi(self, path: str, method: str, summary: str) -> None:
        """Add endpoint to OpenAPI spec"""
        endpoint_signature = f"{method}_{path}"
        if endpoint_signature in self.seen_endpoints:
            return
        
        self.seen_endpoints.add(endpoint_signature)
        
        if path not in self.openapi_spec['paths']:
            self.openapi_spec['paths'][path] = {}
        
        self.openapi_spec['paths'][path][method.lower()] = {
            "summary": summary,
            "responses": {
                "200": {
                    "description": "Successful response",
                    "content": {
                        "application/json": {
                            "schema": {"type": "object"}
                        }
                    }
                }
            }
        }

    def _process_postman_items_for_excel(self, items: List[Dict], sl_no: int) -> int:
        """Process Postman items for Excel format"""
        for item in items:
            if 'item' in item:
                sl_no = self._process_postman_items_for_excel(item['item'], sl_no)
            else:
                result = self._extract_from_postman_request_for_excel(item, sl_no)
                if result:
                    self.excel_results.append(result)
                    sl_no += 1
        return sl_no

    def _extract_from_postman_request_for_excel(self, request: Dict, sl_no: int) -> Optional[Dict]:
        """Extract data from Postman request for Excel format"""
        try:
            method = request.get('request', {}).get('method', 'GET').upper()
            url_obj = request.get('request', {}).get('url', {})
            
            service_url, domain = self._extract_url_and_domain(url_obj)
            
            endpoint_signature = f"{method}_{service_url}"
            if endpoint_signature in self.seen_endpoints:
                return None
            self.seen_endpoints.add(endpoint_signature)
            
            service_type = self._determine_service_type(service_url)
            service_base = self._determine_service_base(service_url)
            
            return {
                "Sl. No": sl_no,
                "Domain": domain,
                "Domain Route Required": "DO you have any other domain / sub-domain for this service?",
                "Base App": self._extract_base_app(domain),
                "Service Type": service_type,
                "Service URL": service_url,
                "Service Base (HTTP/API)": service_base,
                "API Information": self._get_api_information(service_base, method),
                "Method": method,
                "IP Address : Port (external)": "",
                "SSL/TLS Version": ""
            }
            
        except Exception as e:
            print(f"Warning: Failed to process request: {str(e)}")
            return None

    def _process_log_data_for_excel(self, log_lines: List[str]) -> None:
        """Process raw log data for Excel format"""
        sl_no = len(self.excel_results) + 1
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        method_pattern = r'(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+'
        
        for line in log_lines:
            urls = re.findall(url_pattern, line)
            methods = re.findall(method_pattern, line.upper())
            
            for url in urls:
                try:
                    parsed = urlparse(url)
                    domain = parsed.netloc
                    method = methods[0] if methods else "GET"
                    
                    endpoint_signature = f"{method}_{url}"
                    if endpoint_signature in self.seen_endpoints:
                        continue
                    self.seen_endpoints.add(endpoint_signature)
                    
                    service_type = self._determine_service_type(url)
                    service_base = self._determine_service_base(url)
                    
                    result = {
                        "Sl. No": sl_no,
                        "Domain": domain,
                        "Domain Route Required": "DO you have any other domain / sub-domain for this service?",
                        "Base App": self._extract_base_app(domain),
                        "Service Type": service_type,
                        "Service URL": url,
                        "Service Base (HTTP/API)": service_base,
                        "API Information": self._get_api_information(service_base, method),
                        "Method": method,
                        "IP Address : Port (external)": "",
                        "SSL/TLS Version": ""
                    }
                    
                    self.excel_results.append(result)
                    sl_no += 1
                    
                except Exception as e:
                    continue

    def _extract_url_and_domain(self, url_obj) -> tuple:
        """Extract URL and domain from URL object"""
        service_url = ""
        domain = ""
        
        if isinstance(url_obj, dict):
            raw_url = url_obj.get('raw', '')
            if raw_url:
                service_url = raw_url
                try:
                    parsed = urlparse(raw_url)
                    domain = parsed.netloc
                    if ':' in domain:
                        domain = domain.split(':')[0]
                except:
                    if '://' in raw_url:
                        domain = raw_url.split('://')[1].split('/')[0]
            else:
                path_parts = url_obj.get('path', [])
                path = '/'.join(path_parts) if isinstance(path_parts, list) else str(path_parts)
                
                host_info = url_obj.get('host', [])
                if isinstance(host_info, list) and host_info:
                    domain = '.'.join(host_info)
                else:
                    domain = str(host_info)
                
                service_url = f"https://{domain}/{path}" if domain else path
        else:
            service_url = str(url_obj)
            try:
                parsed = urlparse(service_url)
                domain = parsed.netloc
                if ':' in domain:
                    domain = domain.split(':')[0]
            except:
                if '://' in service_url:
                    domain = service_url.split('://')[1].split('/')[0]
        
        domain = domain.replace('{{', '').replace('}}', '').strip()
        service_url = service_url.replace('{{', '').replace('}}', '').strip()
        
        return service_url, domain

    def _determine_service_type(self, url: str) -> str:
        """Determine service type based on URL patterns"""
        url_lower = url.lower()
        
        if any(keyword in url_lower for keyword in ['/auth', '/login', '/logout', '/token', '/oauth', 'auth']):
            return "Auth"
        elif any(keyword in url_lower for keyword in ['/api/', '/v1/', '/v2/', '/v3/', '/rest/', 'api']):
            return "API"
        elif any(keyword in url_lower for keyword in ['/user', '/profile', '/account', 'user']):
            return "User"
        elif any(keyword in url_lower for keyword in ['/payment', '/transaction', '/wallet', 'payment']):
            return "Payment"
        elif any(keyword in url_lower for keyword in ['/report', '/analytics', '/stats', 'report']):
            return "Report"
        else:
            return "General"

    def _determine_service_base(self, url: str) -> str:
        """Determine if it's HTTP or API based"""
        url_lower = url.lower()
        
        if any(keyword in url_lower for keyword in ['/api/', '/v1/', '/v2/', '/v3/', '/rest/']):
            return "API"
        else:
            return "HTTP"

    def _extract_base_app(self, domain: str) -> str:
        """Extract base application name from domain"""
        try:
            if not domain:
                return "Unknown App"
            
            domain_parts = domain.split('.')
            main_parts = [part for part in domain_parts if part not in ['www', 'api', 'auth', 'dev', 'test', 'staging']]
            
            if main_parts:
                main_domain = main_parts[0].capitalize()
                return f"{main_domain} App"
            
            return "Unknown App"
            
        except:
            return "Unknown App"

    def _get_api_information(self, service_base: str, method: str) -> str:
        """Get API information based on service base and method"""
        if service_base == "API":
            return f"{method} based API"
        else:
            return "HTTP based service"

    def _extract_info(self, postman_data: Dict) -> None:
        """Extract collection information for OpenAPI"""
        info = postman_data.get('info', {})
        self.openapi_spec['info']['title'] = info.get('name', 'API Documentation')
        self.openapi_spec['info']['description'] = info.get('description', 'Generated from Postman collection')

    def _extract_variables(self, postman_data: Dict) -> None:
        """Extract variables for OpenAPI"""
        variables = postman_data.get('variable', [])
        for var in variables:
            if isinstance(var, dict) and 'key' in var and 'value' in var:
                self.variables[var['key']] = var['value']

    def save_excel_format(self, output_file: str) -> None:
        """Save results to CSV file (Excel format)"""
        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=self.column_headers)
                writer.writeheader()
                
                for result in self.excel_results:
                    ordered_result = {header: result.get(header, "") for header in self.column_headers}
                    writer.writerow(ordered_result)
            
            print(f"✓ Excel CSV saved: {output_file}")
            
        except Exception as e:
            raise Exception(f"Error saving Excel format: {str(e)}")

    def save_text_format(self, output_file: str) -> None:
        """Save results to text file"""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("API ENDPOINTS REPORT\n")
                f.write("=" * 50 + "\n\n")
                
                for result in self.excel_results:
                    for header in self.column_headers:
                        f.write(f"{header}: {result.get(header, '')}\n")
                    f.write("-" * 30 + "\n")
            
            print(f"✓ Text report saved: {output_file}")
            
        except Exception as e:
            raise Exception(f"Error saving text format: {str(e)}")

    def save_openapi_json(self, output_file: str) -> None:
        """Save OpenAPI specification as JSON"""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.openapi_spec, f, indent=2)
            
            print(f"✓ OpenAPI JSON saved: {output_file}")
            
        except Exception as e:
            raise Exception(f"Error saving OpenAPI JSON: {str(e)}")

    def save_openapi_yaml(self, output_file: str) -> None:
        """Save OpenAPI specification as YAML"""
        try:
            import yaml
            with open(output_file, 'w', encoding='utf-8') as f:
                yaml.dump(self.openapi_spec, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
            
            print(f"✓ OpenAPI YAML saved: {output_file}")
            
        except Exception as e:
            raise Exception(f"Error saving OpenAPI YAML: {str(e)}")

def get_file_choice():
    """Get user choice for file type"""
    print("📁 Choose the type of file you want to scan:")
    print("1. Postman Collection (.json)")
    print("2. Raw Log File (.log, .txt)")
    print("3. PDF Documentation (.pdf)")
    print("4. Exit")
    
    while True:
        choice = input("Enter your choice (1-4): ").strip()
        if choice in ['1', '2', '3', '4']:
            return choice
        print("Please enter a valid choice (1-4)")

def get_file_path(file_type):
    """Get file path from user"""
    file_extensions = {
        '1': ['.json'],
        '2': ['.log', '.txt'],
        '3': ['.pdf']
    }
    
    extensions = file_extensions.get(file_type, [])
    ext_text = ", ".join(extensions)
    
    print(f"\n📂 Please provide the path to your {['Postman JSON', 'Log', 'PDF'][int(file_type)-1]} file")
    print(f"   Supported formats: {ext_text}")
    
    while True:
        file_path = input("File path: ").strip().strip('"')
        
        if not file_path:
            print("Please enter a file path")
            continue
        
        if not os.path.isfile(file_path):
            print(f"File not found: {file_path}")
            print("Please check the path and try again")
            continue
        
        file_ext = Path(file_path).suffix.lower()
        if extensions and file_ext not in extensions:
            print(f"This file type ({file_ext}) may not be supported for this choice")
            confirm = input("Do you want to try anyway? (y/n): ").strip().lower()
            if confirm != 'y':
                continue
        
        return file_path

def main():
    print("🚀 Welcome to Unified API Scanner!")
    print("=" * 40)
    
    # Install dependencies
    if not DependencyInstaller.install_dependencies():
        print("Some dependencies could not be installed. The scanner may not work properly.")
        return
    
    # Get user choices
    choice = get_file_choice()
    if choice == '4':
        print("Goodbye! 👋")
        return
    
    file_path = get_file_path(choice)
    
    # Create output directory
    base_name = Path(file_path).stem
    output_dir = f"{base_name}_output"
    os.makedirs(output_dir, exist_ok=True)
    
    # Process file
    scanner = UnifiedAPIScanner()
    
    print(f"\n🔍 Processing your file...")
    try:
        if choice == '1':
            success = scanner.process_postman_collection(file_path)
        elif choice == '2':
            success = scanner.process_raw_logs(file_path)
        elif choice == '3':
            success = scanner.process_pdf_file(file_path)
        
        if success:
            # Generate outputs
            excel_output = os.path.join(output_dir, f"{base_name}_endpoints.csv")
            text_output = os.path.join(output_dir, f"{base_name}_report.txt")
            json_output = os.path.join(output_dir, f"{base_name}_openapi.json")
            yaml_output = os.path.join(output_dir, f"{base_name}_openapi.yaml")
            
            scanner.save_excel_format(excel_output)
            scanner.save_text_format(text_output)
            scanner.save_openapi_json(json_output)
            scanner.save_openapi_yaml(yaml_output)
            
            print(f"\n🎉 Processing completed successfully!")
            print(f"📁 All files saved to: {output_dir}")
            print(f"   • Excel CSV: {excel_output}")
            print(f"   • Text Report: {text_output}")
            print(f"   • OpenAPI JSON: {json_output}")
            print(f"   • OpenAPI YAML: {yaml_output}")
            print(f"\n📊 Total endpoints found: {len(scanner.excel_results)}")
            
        else:
            print("❌ Processing failed. Please check your file format.")
            
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        print("Please make sure you're using the correct file format.")

if __name__ == "__main__":
    main()