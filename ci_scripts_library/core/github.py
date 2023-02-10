"""
derived classes using PyGithub base class
plus extra utility functions"""

import re
import json
from typing import Dict, List
from github import Github
from github.Issue import Issue
from ci_scripts_library.core.github_models import (
    IssueAndMetadata, 
    IssueMetadata
)

class GithubWithIssueMetadata(Github):
    def get_metadata(
        self, 
        repo_full_name: str,
        issue_number: int,
        metadata_prefix: str
    ) -> Dict:
        """ 
        return metadata key/value pair for the issue for given metadata_prefix
        """
        issue = self.get_repo(repo_full_name).get_issue(number=issue_number)   
        return self.get_metadata_from_body(issue.body, metadata_prefix)
    
    def set_metadata(
        self, 
        repo_full_name: str, 
        issue_id: int, 
        metadata_prefix: str, 
        metadata_key: str, 
        metadata_value: str
    ):
        """
        if metadata_key does not exist for metadata_prefix, then add new key/value pair
        if metadata_key does exist, update the existing value
        """
        pass
    
    def format_metadata_entry(
        self,
        metadata_prefix: str,
        metadata_key: str,
        metadata_value: str
    ) -> str:
        data = { metadata_key: metadata_value }
        return f'\n<!-- {metadata_prefix} = {json.dumps(data)} -->'

    def create_issue_with_metadata(
        self,
        repo_full_name: str,
        metadata_prefix: str,
        metadata_key: str,
        metadata_value: str,
        title: str,
        body: str,
        **kwargs
    ) -> Issue:
        MAX_ISSUE_CHARS: int = 65536
        DETAILED_PATH_STRING: str = "Introduced through"

        metadata_entry = self.format_metadata_entry(metadata_prefix, metadata_key, metadata_value)
        #print(f"metadata_entry: {metadata_entry}")
        body = f"{body}\n\n{metadata_entry}"

        new_body = body

        # handle case where body is greater than maximum allowed characters
        n_chars_body = len(body)
        #print(f"{n_chars_body=}")
        if n_chars_body > MAX_ISSUE_CHARS:
           # first see by how much we are exceeding the limit
           n_chars_to_remove = n_chars_body - MAX_ISSUE_CHARS
           print(f"{n_chars_to_remove=}")
           
           # now let's see how many chars are used by the Detailed paths section
           # loop over body
           n_char_count = 0
           for line in body.splitlines():
               # print(f"{line=}")
               if DETAILED_PATH_STRING in line:
                 n_char_count += len(line)
           
           #print(f"{n_char_count=}") 
           
           n_paths_char_to_keep = n_char_count - n_chars_to_remove

           #rebuild body while trimming down the detailed paths
           new_body = ""
           n_paths_char_count = 0
           for line in body.splitlines():
               if DETAILED_PATH_STRING in line:
                   n_paths_char_count += len(line)
                   if n_paths_char_count < n_paths_char_to_keep:
                       new_body += line
               else:
                   new_body += line

        #print(f"{len(new_body)=}")
        return self.get_repo(repo_full_name).create_issue(title=title, body=new_body, **kwargs)
    
    def get_metadata_from_body(self, issue_body: str, metadata_prefix: str) -> IssueMetadata:
        
        metadata = None
        METADATA_REGEX = '\<\!-- {metadata_prefix} = (.*) --\>'
    
        # typer.echo(f"issue_body: {issue_body}")
        # regex out the metadata
        match = re.search(
            f'<!--\s{metadata_prefix}\s=\s(.*)\s-->',
            str(issue_body),
            re.IGNORECASE
        )
    
        if match:
            # print(f"match: {match.group(1)}")
            metadata = json.loads(match.group(1))
    
        return metadata
    
    def get_repo_issues_and_metadata(
        self,
        repo_full_name: str,
        metadata_prefix: str
    ) -> List[IssueAndMetadata]:
        """
        combine the complete set of issues for a repo with
        their associated metadata parsed
        """
        open_issues_metadata: list = []
        for issue in self.get_repo(repo_full_name).get_issues(state="open"):
            issue_metadata = self.get_metadata_from_body(issue.body, metadata_prefix)
            if not issue.pull_request:
                open_issues_metadata.append(
                    IssueAndMetadata(
                        issue_number=issue.number,
                        issue_repo_full_name=repo_full_name,
                        issue=issue,
                        issue_metadata=issue_metadata
                    )
                )
        return open_issues_metadata 