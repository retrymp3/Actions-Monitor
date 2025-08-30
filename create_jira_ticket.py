#!/usr/bin/env python3

import os
import json
import requests
import base64
import urllib3
from typing import Dict, List, Optional
import argparse
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

JIRA_BASE_URL = os.environ.get("JIRA_BASE_URL", "https://<base-url>")
JIRA_API_USER = os.environ.get("JIRA_API_USER", "<user-email>")
JIRA_API_TOKEN = os.environ.get("JIRA_API_TOKEN", "")
JIRA_PROJECT_KEY = os.environ.get("JIRA_PROJECT_KEY", "<project_KEY>")

SEVERITY_MAP = {
    "ERROR": "Critical",
    "WARNING": "High", 
    "INFO": "Medium",
    "DEBUG": "Low"
}

PRIORITY_MAP = {
    "ERROR": "P1",
    "WARNING": "P2",
    "INFO": "P3",
    "DEBUG": "P4"
}


class JiraTicketCreator:    
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        
        if JIRA_API_USER and JIRA_API_TOKEN:
            self._setup_authentication()
        else:
            print("JIRA_API_USER or JIRA_API_TOKEN not set")
    
    def _setup_authentication(self):
        auth_string = f"{JIRA_API_USER}:{JIRA_API_TOKEN}"
        auth_bytes = auth_string.encode('ascii')
        auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
        self.session.headers.update({
            'Authorization': f'Basic {auth_b64}',
            'Content-Type': 'application/json'
        })
    
    def check_issue_exists(self, file_path: str, line: int, cwe: str) -> bool:
        try:
            file_location = f"{file_path}:{line}"
            jql = f'project = {JIRA_PROJECT_KEY} AND description ~ "{file_location}" AND issuetype = Bug'
            
            response = self.session.get(
                f"{JIRA_BASE_URL}/rest/api/3/search",
                params={'jql': jql, 'maxResults': 10}
            )
            
            if response.status_code == 200:
                search_results = response.json()
                if search_results['total'] > 0:
                    for issue in search_results['issues']:
                        issue_summary = issue['fields']['summary']
                        if cwe in issue_summary:
                            print(f"🔍 Found duplicate issue: {issue['key']} (same location and CWE)")
                            return True
                    
                    print(f"🔍 Found issue at same location but different CWE - creating new ticket")
                    return False
                return False
            else:
                print(f"Failed to search for duplicates: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"Error checking for duplicates: {e}")
            return False
    
    def _create_custom_details_json(self, cwe: str) -> Dict:
        return {
            "CWE": [cwe],
            "raised_by": os.environ.get('GITHUB_ACTOR', 'Unknown'),
            "repo": f"https://github.com/{os.environ.get('GITHUB_REPOSITORY', 'unknown/repo')}",
            "Summary": f"https://github.com/{os.environ.get('GITHUB_REPOSITORY', 'unknown/repo')}/actions/runs/{os.environ.get('GITHUB_RUN_ID', 'unknown')}"
        }
    
    def _create_description_table(self, message: str, rule: str, file_path: str, line: int, 
                                severity_value: str, cwe: str, signature: str) -> List[Dict]:
        return [
            {
                "type": "table",
                "content": [
                    {
                        "type": "tableRow",
                        "content": [
                            {"type": "tableHeader", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Field"}]}]},
                            {"type": "tableHeader", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Details"}]}]}
                        ]
                    },
                    {
                        "type": "tableRow",
                        "content": [
                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "📝 Summary"}]}]},
                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": message}]}]}
                        ]
                    },
                    {
                        "type": "tableRow",
                        "content": [
                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "🔍 Rule"}]}]},
                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": rule}]}]}
                        ]
                    },
                    {
                        "type": "tableRow",
                        "content": [
                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "🌐 Affected Endpoint"}]}]},
                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": f"https://github.com/{os.environ.get('GITHUB_REPOSITORY', 'unknown/repo')}/blob/main/{file_path}#L{line}", "marks": [{"type": "code"}]}]}]}
                        ]
                    },
                    {
                        "type": "tableRow",
                        "content": [
                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "🚨 Severity"}]}]},
                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": severity_value}]}]}
                        ]
                    },
                    {
                        "type": "tableRow",
                        "content": [
                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "🆔 CWE"}]}]},
                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": cwe}]}]}
                        ]
                    },
                    {
                        "type": "tableRow",
                        "content": [
                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "🔑 Signature"}]}]},
                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": signature}]}]}
                        ]
                    },
                    {
                        "type": "tableRow",
                        "content": [
                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "⚠️ Impact"}]}]},
                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Security vulnerability detected that could allow potential exploitation"}]}]}
                        ]
                    },
                    {
                        "type": "tableRow",
                        "content": [
                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "📚 References"}]}]},
                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "GitHub Actions Security", "marks": [{"type": "link", "attrs": {"href": "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions"}}]}]}]}
                        ]
                    }
                ]
            }
        ]
    
    def create_issue(self, cwe: str, message: str, severity: str, rule: str, 
                    file_path: str, line: int) -> Optional[str]:
        try:
            signature = f"{cwe}-{file_path}-{line}"
            print(f"📌 Creating issue for: {cwe} in {file_path}:{line}")
            
            if self.check_issue_exists(file_path, line, cwe):
                print(f"⏭️ Skipping duplicate issue: {cwe} at {file_path}:{line}")
                return None
            
            severity_value = SEVERITY_MAP.get(severity, "Medium")
            priority = PRIORITY_MAP.get(severity, "P3")
            
            description_content = self._create_description_table(
                message, rule, file_path, line, severity_value, cwe, signature
            )
            
            custom_details = self._create_custom_details_json(cwe)
            description_content.extend([
                {
                    "type": "paragraph",
                    "content": [{"type": "text", "text": "🔍 Details:", "marks": [{"type": "strong"}]}]
                },
                {
                    "type": "codeBlock",
                    "attrs": {"language": "json"},
                    "content": [{"type": "text", "text": json.dumps(custom_details, indent=2)}]
                }
            ])
            
            payload = {
            payload = {
                "fields": {
                    "project": {"key": JIRA_PROJECT_KEY},
                    "summary": cwe,
                    "issuetype": {"name": "Bug"},
                    "description": {
                        "type": "doc",
                        "version": 1,
                        "content": description_content
                    },
                    "customfield_10014": "SSD-458",
                    "customfield_10216": {"value": severity_value},
                    "customfield_10218": {"value": "External Facing"},
                    "customfield_10219": {"value": "Injection"},
                    "customfield_10285": {"value": "SAST"}
                }
            }
            
            print(f"📤 Creating Jira issue...")
            
            response = self.session.post(
                f"{JIRA_BASE_URL}/rest/api/3/issue",
                json=payload
            )
            
            if response.status_code == 201:
                issue_data = response.json()
                issue_key = issue_data['key']
                issue_url = f"{JIRA_BASE_URL}/browse/{issue_key}"
                print(f"Created Jira issue: {issue_key}")
                print(f"🔗 View at: {issue_url}")
                return issue_key
            else:
                print(f"Failed to create issue: {response.status_code}")
                print(f"   Response: {response.text}")
                return None
                
        except Exception as e:
            print(f"Error creating issue: {e}")
            return None


def load_semgrep_results(file_path: str) -> List[Dict]:
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        results = data.get('results', [])
        print(f"📊 Loaded {len(results)} results from {file_path}")
        return results
        
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return []
    except json.JSONDecodeError as e:
        print(f"Invalid JSON in {file_path}: {e}")
        return []
    except Exception as e:
        print(f"Error loading {file_path}: {e}")
        return []


def validate_environment() -> bool:
    required_vars = [JIRA_BASE_URL, JIRA_API_USER, JIRA_API_TOKEN, JIRA_PROJECT_KEY]
    if not all(required_vars):
        print(" Missing required environment variables:")
        print(f"   JIRA_BASE_URL: {'✅' if JIRA_BASE_URL else '❌'}")
        print(f"   JIRA_API_USER: {'✅' if JIRA_API_USER else '❌'}")
        print(f"   JIRA_API_TOKEN: {'✅' if JIRA_API_TOKEN else '❌'}")
        print(f"   JIRA_PROJECT_KEY: {'✅' if JIRA_PROJECT_KEY else '❌'}")
        print("\n💡 These should be set as GitHub Secrets in your workflow")
        return False
    return True


def process_results(results: List[Dict], creator: JiraTicketCreator) -> tuple:
    created_issues = []
    skipped_issues = []
    failed_issues = []
    
    print(f"\n📋 Processing {len(results)} security findings...")
    
    for i, result in enumerate(results, 1):
        try:
            cwe = result.get('extra', {}).get('metadata', {}).get('cwe', ['Unknown CWE'])[0]
            message = result.get('extra', {}).get('message', 'No message')
            severity = result.get('extra', {}).get('severity', 'INFO')
            rule = result.get('check_id', 'Unknown rule')
            file_path = result.get('path', 'Unknown file')
            line = result.get('start', {}).get('line', 0)
            
            jira_severity = SEVERITY_MAP.get(severity, "Medium")
            
            print(f"\n Processing {i}/{len(results)}: {cwe}")
            print(f"   File: {file_path}:{line}")
            print(f"   Severity: {severity} -> {jira_severity}")
            
            if jira_severity not in ["Critical", "High"]:
                print(f"   Skipping {jira_severity} severity issue")
                skipped_issues.append(f"{cwe} in {file_path}:{line} (severity: {jira_severity})")
                continue
            
            issue_key = creator.create_issue(cwe, message, severity, rule, file_path, line)
            
            if issue_key:
                created_issues.append(issue_key)
            elif issue_key is None:
                skipped_issues.append(f"{cwe} in {file_path}:{line}")
            else:
                failed_issues.append(f"{cwe} in {file_path}:{line}")
                
        except Exception as e:
            print(f"Error processing result {i}: {e}")
            failed_issues.append(f"Result {i}")
    
    return created_issues, skipped_issues, failed_issues


def print_summary(created_issues: List[str], skipped_issues: List[str], failed_issues: List[str]):
    print(f"\n{'='*50}")
    print(f"📊 SUMMARY")
    print(f"{'='*50}")
    print(f"Created: {len(created_issues)} tickets")
    print(f"Skipped: {len(skipped_issues)} duplicates")
    print(f"Failed: {len(failed_issues)} issues")
    
    if created_issues:
        print(f"\n🎫 Created tickets:")
        for issue_key in created_issues:
            print(f"   • {issue_key}")
    
    if failed_issues:
        print(f"\nFailed to create tickets for:")
        for failure in failed_issues:
            print(f"   • {failure}")


def write_github_outputs(created_issues: List[str], skipped_issues: List[str]):
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
            f.write(f"jira_tickets_created={len(created_issues)}\n")
            f.write(f"jira_tickets_skipped={len(skipped_issues)}\n")
            if created_issues:
                f.write("jira_ticket_keys<<EOF\n")
                for issue_key in created_issues:
                    f.write(f"{issue_key}\n")
                f.write("EOF\n")


def main():
    parser = argparse.ArgumentParser(description="Create Jira tickets from Semgrep results")
    parser.add_argument("--results", "-r", default="semgrep-results.json", 
                       help="Path to Semgrep results JSON file")

    
    args = parser.parse_args()
    
    if not validate_environment():
        sys.exit(1)
    
    if not os.path.exists(args.results):
        print(f"Results file not found: {args.results}")
        print("💡 Make sure you have run Semgrep first and have results to process")
        sys.exit(1)
    
    results = load_semgrep_results(args.results)
    if not results:
        print("No security issues found - exiting successfully")
        sys.exit(0)
    
    creator = JiraTicketCreator()
    created_issues, skipped_issues, failed_issues = process_results(
        results, creator
    )
    
    print_summary(created_issues, skipped_issues, failed_issues)
    
    if failed_issues:
        print(f"\nFailed to create {len(failed_issues)} tickets - exiting with error")
        sys.exit(1)
    
    write_github_outputs(created_issues, skipped_issues)
    
    print(f"\nSuccessfully processed all security findings!")


if __name__ == "__main__":
    main()
