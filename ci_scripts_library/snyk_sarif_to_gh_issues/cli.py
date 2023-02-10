import typer
import os
import sys
import time

from ci_scripts_library.core.github import GithubWithIssueMetadata as Github
from ci_scripts_library.core.utils import (
    load_json_file,
    construct_vulndb_url,
    get_repo_full_name_from_repo_url
)

app = typer.Typer(add_completion=False)

# globals
METADATA_PREFIX = "snyk_sarif_to_gh_issues"
METADATA_KEY_ID = "id"
g = {}

@app.callback()
def main(ctx: typer.Context,
    github_token: str = typer.Option(
        None,
        envvar="GITHUB_TOKEN",
        help="GitHub access token, if not set here will load from ENV VAR GITHUB_TOKEN"
    ),
    snyk_sarif_file: str = typer.Option(
        "snyk.sarif",
        envvar="SNYK_SARIF_FILE",
        help="Path to Snyk CLI sarif output file"
    ),
    remote_repo_url: str = typer.Option(
        None,
        envvar="REMOTE_REPO_URL",
        help="git url, e.g. https://github.com/owner/repo.git"
    )
):
    """" 
    entrypoint for application
    """
    g['github_token'] = github_token
    g['snyk_sarif_file'] = snyk_sarif_file
    g['repo_full_name'] = get_repo_full_name_from_repo_url(remote_repo_url)
    typer.echo(f"{remote_repo_url=}")
    # typer.echo(f"{g['repo_full_name']=}")

    g['gh_client'] = Github(g['github_token'])
    typer.echo(f"Github client created successfully")

    g['snyk_sarif'] = load_json_file(g['snyk_sarif_file'])
    typer.echo(f"Snyk SARIF file loaded")

    # load rules from sarif
    g['runs'] = g['snyk_sarif']['runs']
    # typer.echo(f"{len(g['runs'])} Snyk Projects found in output")

    g['repo_open_issues'] = g['gh_client'].get_repo_issues_and_metadata(g['repo_full_name'], METADATA_PREFIX)
    typer.echo(f"{len(g['repo_open_issues'])} Open GH Issues retrieved")

    typer.echo("----------------------------")
    return

@app.command()
def create_new_issues():
    """
    Create Github Issues from the detected Snyk Issues
    """
    typer.echo(f"Starting issues creation for {len(g['runs'])} Snyk projects...")

    gh_client: Github = g['gh_client']
    # rules = g['rules']
    # results = g['results']

    for run in g['runs']: # handles snyk test --all-projects output
        rules = run['tool']['driver']['rules']
        results = run['results']
        for result in results:
            gh_issue_exists: bool = False
            # print(result)
            locationUri = result['locations'][0]['physicalLocation']['artifactLocation']['uri']
            rule_id = result['ruleId']
    
            # for each single issue find the rule text to create the issue
            matching_rule = [x for x in rules if x['id'] == rule_id].pop()
    
            snyk_issue_id = f"{locationUri}/{rule_id}"
    
            print(f" - {snyk_issue_id}, ", end="")
    
            title = f"{matching_rule['shortDescription']['text']} ({locationUri})"
            body = (
                f"{matching_rule['help']['markdown']} <br/> "
                f"[{rule_id}]({construct_vulndb_url(rule_id)}) <br/> "
                f"{matching_rule['fullDescription']['text']}"
            )
    
            gh_issue_exists = snyk_issue_id in \
                [x.issue_metadata['id'] for x in g['repo_open_issues'] if x.issue_metadata is not None]
    
            if gh_issue_exists:
                print(f"already exists (skip)")
                pass
            else:
                print(f"does not exist (create)")
                gh_client.create_issue_with_metadata(
                    repo_full_name=g['repo_full_name'],
                    metadata_prefix=METADATA_PREFIX,
                    metadata_key=METADATA_KEY_ID,
                    metadata_value=snyk_issue_id,
                    title=title,
                    body=body
                )
                time.sleep(2)

            

@app.command()
def close_fixed_issues():
    """
    Close Github Issues when matching snyk Issue is no longer found
    """
    typer.echo("Checking for fixed Github Issues to close...")
    gh_client: Github = g['gh_client']

    for issue in g['repo_open_issues']:
        if issue.issue_metadata: #ensure we are only processing GH issues with metadata
            snyk_issue_exists: bool = False
            print(f" - {issue.issue_metadata[METADATA_KEY_ID]}, ", end="")
            for run in g['runs']:
                results = run['results']
                for result in results:
                    locationUri = result['locations'][0]['physicalLocation']['artifactLocation']['uri']
                    rule_id = result['ruleId']
                    snyk_issue_id = f"{locationUri}/{rule_id}"
                    snyk_issue_exists = (
                        issue.issue_metadata[METADATA_KEY_ID] == snyk_issue_id
                    )
        
                    if snyk_issue_exists:
                        print(f"still exists (skip)")
                        break
                
                if not snyk_issue_exists:
                    print(f"no longer exists (close)")
                    # close the github issue
                    issue.issue.edit(state="closed")
                    issue.issue.create_comment("auto-closed by `snyk_sarif_to_gh_issues`\nreason: snyk issues no longer exists")
                    time.sleep(2)
        
@app.command()
def sync_issues():
    """
    create new issues and close fixed issues in a single command
    """
    create_new_issues()
    close_fixed_issues()

if __name__ == "__main__":
    app()
