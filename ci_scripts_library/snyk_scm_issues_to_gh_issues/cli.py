import time
import typer
import sys
import re
import json
import requests
import os

from enum import Enum

from ci_scripts_library.core.github_models import IssueAndMetadata

sys.path.append("../../ci_scripts_library")

from ci_scripts_library.core.github import GithubWithIssueMetadata as GitHub
from ci_scripts_library.core.utils import *
from ci_scripts_library.core import SuperSnykClient
from snyk.models import Project

app = typer.Typer(add_completion=False)

class TrueFalse(Enum):
    l_true = "true"
    l_false = "false"
    u_true = "True"
    u_false = "False"

# globals
METADATA_PREFIX = "snyk_scm_issues_to_gh_issues"
METADATA_KEY_ID = "id"
g = {}

@app.callback()
def main(ctx: typer.Context,
    github_token: str = typer.Option(
        None,
        envvar="GH_TOKEN",
        help="GitHub access token, if not set here will load from ENV VAR GITHUB_TOKEN"
    ),
    github_org: str = typer.Option(
        None,
        envvar="GITHUB_ORG",
        help="GitHub access token, if not set here will load from ENV VAR GITHUB_TOKEN"
    ),
    snyk_token: str = typer.Option(
        None,
        envvar="SNYK_TOKEN",
        help="Please specify your Snyk token. https://docs.snyk.io/tutorials/amazon-web-services/aws-code-suite/snyk-security/create-account-and-obtain-a-token"
    ),

    remote_repo_url: str = typer.Option(
        None,
        envvar="REMOTE_REPO_URL",
        help="full name of the github repo e.g. owner/repo"
    ),
    snyk_prefix: str = typer.Option(
        "",
        envvar="SNYK_PREFIX",
        help="Prefix for Snyk organization"
    ),
    use_fresh_issues: TrueFalse = typer.Option(
        "false",
        envvar="USE_FRESH_ISSUES",
        help="when running on push to monitored branch, set this to true to ensure latest snyk results are used"
    )
):

    # convert use_fresh_issues to python bool
    use_fresh_issues: bool = (use_fresh_issues.value.lower() in ["true", "True"])

    g['github_token'] = github_token
    g['github_org'] = github_org
    typer.echo(g['github_org'])
    
    snyk_token = snyk_token.replace(',', '')
    g['snyk_token'] = snyk_token
    # g['remote_repo_url'] = remote_repo_url
    g['remote_repo_url'] = remote_repo_url
    typer.echo(g['remote_repo_url'])
    # g['snyk_prefix']= snyk_prefix
    g['snyk_prefix']= ""
    g['delay']= 15
    g['retry']= 5

    typer.echo(g['snyk_token'])
    typer.echo(g['github_token'])

    g['github_client'] = GitHub(g['github_token'])
    typer.echo("Github client created successfully")

    g['snyk_client'] = SuperSnykClient("6d8b2237-962b-4fbe-8c15-2a89a8849d1d")
    typer.echo("Snyk client created successfully")

    # g['snyk_client'] = SuperSnykClient(snyk_t)
    # typer.echo("Snyk client created successfully")
    
    # typer.echo("Running GitHub org method ")
    # g['github_org'] = get_github_org_name(g['remote_repo_url'])

    
    # g['github_org'] = "rhicksiii91"
    # g['snyk_org'] = find_snyk_org_from_github_org(g['snyk_client'], g['github_org'], g['snyk_prefix'])
    g['snyk_org'] = find_snyk_org_from_github_org(g['snyk_client'], g['github_org'])

    if not g['snyk_org']:
        sys.exit(f"Can not find GitHub organization in Snyk.  Check Snyk to make sure {g['github_org']} is the current Snyk organization slug.")

    g['repo_full_name'] = get_repo_full_name_from_repo_url(remote_repo_url)
    g['github_org'] = get_github_org_name(remote_repo_url)
    g['github_repo'] = get_github_repo_name(remote_repo_url)
    g['repo_open_issues'] = g['github_client'].get_repo_issues_and_metadata(g['repo_full_name'], METADATA_PREFIX)

    g['snyk_open_projects'] = get_snyk_open_projects_for_repo_target(g['snyk_client'], g['snyk_org'], g['repo_full_name'])

    g['fresh_snyk_projects_with_issues'] = []

    # when we don't care about exact freshness (e.g. daily/weekly sync)
    # then we get use the projects and issues we have right now and consider
    # what we get when the script starts as "fresh"
    if not use_fresh_issues:
        g['fresh_snyk_projects_with_issues'] = build_projects_with_issues_from_snyk_projects(g['snyk_open_projects'])
        # print(f"{g['fresh_snyk_projects_with_issues']=}")
    
    typer.echo(f"{use_fresh_issues=}")
    typer.echo("----------------------------")
    return

@app.command()
def create_new_issues():
    """
    Create Github Issues from the detected Snyk Issues
    """
    
    gh_repo_full_name = (g['repo_full_name'])

    pending_projects =  g['snyk_open_projects'].copy()
    retry_counter = 1

    while (len(pending_projects) > 0 and retry_counter <= g['retry']):

        ready_projects = []
        
        print(f"({retry_counter}) Finding projects ready for Issue creation...")
        # find the projects that are ready
        for project in pending_projects:
            fresh_project_with_issues = list(
                filter(
                    lambda x: (x.project == project),
                    g['fresh_snyk_projects_with_issues'])
            )
            #if project in [x['project'] for x in g['fresh_snyk_projects_with_issues']]:
            if fresh_project_with_issues:
                print(f"checking if ready: {project['id']=}, {project['name']=}, True (from cache)")
                ready_projects.append(fresh_project_with_issues[0])
            
            elif is_snyk_project_fresh(project['lastTestedDate']):
                print(f"checking if ready: {project['id']=}, {project['name']=}, True")
                ready_projects.extend(build_projects_with_issues_from_snyk_projects([project]))
                # allows us to track projects that can be processed from any function
                g['fresh_snyk_projects_with_issues'].extend(ready_projects)
            
            else:
                print(f"checking if ready: {project['id']=}, {project['name']=}, False")

        if ready_projects: 
            #ready_projects_with_issues = build_projects_with_issues_from_snyk_projects(ready_projects)
            typer.echo(f"Starting issues creation for {len(ready_projects)} Snyk projects...")
            create_github_issues_for_snyk_projects_with_issues(ready_projects)
        
            
            #g['fresh_snyk_projects_with_issues'].extend(ready_projects_with_issues) 
            
            for project in ready_projects:
                pending_projects.remove(project.project)
        
        retry_counter += 1     

        if pending_projects and retry_counter < g['retry']:
            g['snyk_open_projects'] =  get_snyk_open_projects_for_repo_target(g['snyk_client'], g['snyk_org'], g['repo_full_name'])
            #print(f"{g['snyk_open_projects']=}")
            #print(f"{pending_projects=}")
            # update pending with the latest project data including the lastTestedDate
            for pending_project in pending_projects:
                pending_project['lastTestedDate'] = [x for x in g['snyk_open_projects'] if x['id'] ==  pending_project['id']][0]['lastTestedDate']
            #print(f"{pending_projects=}")
            
            print("Sleeping...")
            time.sleep(g['delay'])
        

@app.command()
def close_fixed_issues():
    """
    Close Github Issues when matching snyk Issue is no longer found
    """
    typer.echo("Checking for fixed Github Issues to close...")
    github_client = g['github_client']
    pending_gh_issues = g['repo_open_issues'].copy()

    retry_counter = 1
    #fresh_projects_with_issues = get_snyk_ready_projects_with_issues(g['snyk_client'], g['snyk_org'], g['repo_full_name'])
    #snyk_issue_ids = create_github_issue_key_list(g['snyk_open_projects'])

    ready_gh_issues = []

    while (pending_gh_issues and retry_counter <= g['retry']):
        for gh_issue in pending_gh_issues:
            snyk_project = get_project_from_gh_issue(gh_issue)
            snyk_issue_exists: bool = False
            print(f" - gh_issue_metadata_value={gh_issue.issue_metadata[METADATA_KEY_ID]}, ", end="")
            if snyk_project:
                snyk_project_fresh = False
                manifest_file_path = '/'.join(gh_issue.issue_metadata[METADATA_KEY_ID].split('/')[:-1])
                #print(f"{manifest_file_path=}")
                # if this gh issues snyk project is fresh then any missing issues for
                # this corresponding snyk project can be closed in github
                if (manifest_file_path in \
                    [get_manifest_file_path_from_snyk_project_name(x.project['name']) for x in g['fresh_snyk_projects_with_issues']]
                ):
                    snyk_project_fresh = True
                    #print("found manifest in fresh projects list")
                elif is_snyk_project_fresh(get_project_from_gh_issue(gh_issue)['lastTestedDate']):
                    snyk_project_fresh = True
                    g['fresh_snyk_projects_with_issues'].extend(build_projects_with_issues_from_snyk_projects([snyk_project]))

                # if snyk project is fresh, check whether this issue still exists
                if snyk_project_fresh:

                    #print(f"{snyk_project=}")
                    snyk_issues = [x.issues for x in g['fresh_snyk_projects_with_issues'] if x.project['id'] == snyk_project['id']]
                    for snyk_issue in snyk_issues[0]['issues']:
                        #for snyk_issue in snyk_issues['issues']:
                        snyk_issue_id_for_gh = get_manifest_file_path_from_snyk_project_name(snyk_project['name']) + f"/{snyk_issue['id']}"
                        #print(f" - {snyk_issue_id_for_gh=}, ", end="")
                        #print(f"comparing {gh_issue.issue_metadata[METADATA_KEY_ID]} and {snyk_issue_id_for_gh}")
                        snyk_issue_exists = (
                            gh_issue.issue_metadata[METADATA_KEY_ID] == f"{snyk_issue_id_for_gh}"
                        )
                        if snyk_issue_exists:
                            #print("found issue")
                            break
                        
                    if not snyk_issue_exists:
                        # close the github issue
                        print("no longer exists (close)")
                        gh_issue.issue.edit(state="closed")
                        gh_issue.issue.create_comment("auto-closed by `snyk_scm_issues_to_gh_issues`\nreason: issue no longer exists")
                        time.sleep(3)
                    else:
                        print("still exists (skip)")  
                
                    pending_gh_issues.remove(gh_issue)
                    
                else: # project not fresh, will stayin as pending checked again
                    print(f"project not fresh for issue")
                    pass
            else:
                # project no longer exists, lets close all of the corresponding GH issues
                # close the github issue
                print(f"project no longer exists in Snyk (close)")
                gh_issue.issue.edit(state="closed")
                gh_issue.issue.create_comment("auto-closed by `snyk_scm_issues_to_gh_issues`\nreason: snyk project no longer exists")
                pending_gh_issues.remove(gh_issue)
                time.sleep(3)

        retry_counter += 1            

        if pending_gh_issues and retry_counter < g['retry']:
            g['snyk_open_projects'] = get_snyk_open_projects_for_repo_target(g['snyk_client'], g['snyk_org'], g['repo_full_name'])            
            print("Sleeping...")
            time.sleep(g['delay'])   
          

@app.command()
def sync_issues():
    close_fixed_issues()
    create_new_issues()

@app.command()
def snyk_license_check():
    """
    Snyk License to look for high and medium issues
    """
    
    gh_repo_full_name = (g['repo_full_name'])

    pending_projects =  g['snyk_open_projects'].copy()
    retry_counter = 1

    while (len(pending_projects) > 0 and retry_counter <= g['retry']):

        ready_projects = []
        
        print(f"({retry_counter}) Finding projects ready for Issue creation...")
        # find the projects that are ready
        for project in pending_projects:
            fresh_project_with_issues = list(
                filter(
                    lambda x: (x.project == project),
                    g['fresh_snyk_projects_with_issues'])
            )
            #if project in [x['project'] for x in g['fresh_snyk_projects_with_issues']]:
            if fresh_project_with_issues:
                print(f"checking if ready: {project['id']=}, {project['name']=}, True (from cache)")
                ready_projects.append(fresh_project_with_issues[0])
            
            elif is_snyk_project_fresh(project['lastTestedDate']):
                print(f"checking if ready: {project['id']=}, {project['name']=}, True")
                ready_projects.extend(build_projects_with_issues_from_snyk_projects([project]))
                # allows us to track projects that can be processed from any function
                g['fresh_snyk_projects_with_issues'].extend(ready_projects)
            
            else:
                print(f"checking if ready: {project['id']=}, {project['name']=}, False")

        if ready_projects: 
            #ready_projects_with_issues = build_projects_with_issues_from_snyk_projects(ready_projects)
            typer.echo(f"Starting issues creation for {len(ready_projects)} Snyk projects...")

            for project in ready_projects:
                license_info = snyk_license_endpoint(g['snyk_token'], g['snyk_org'], project.id)
                print(license_info)

            # create_github_issues_for_snyk_projects_with_issues(ready_projects)
        
            
            #g['fresh_snyk_projects_with_issues'].extend(ready_projects_with_issues) 
            
        #     for project in ready_projects:
        #         pending_projects.remove(project.project)
        
        # retry_counter += 1     

        # if pending_projects and retry_counter < g['retry']:
        #     g['snyk_open_projects'] =  get_snyk_open_projects_for_repo_target(g['snyk_client'], g['snyk_org'], g['repo_full_name'])
        #     #print(f"{g['snyk_open_projects']=}")
        #     #print(f"{pending_projects=}")
        #     # update pending with the latest project data including the lastTestedDate
        #     for pending_project in pending_projects:
        #         pending_project['lastTestedDate'] = [x for x in g['snyk_open_projects'] if x['id'] ==  pending_project['id']][0]['lastTestedDate']
        #     #print(f"{pending_projects=}")
            
        #     print("Sleeping...")
        #     time.sleep(g['delay'])

def snyk_license_endpoint(token, orgId, projectId):
    body = {
    "filters": {
      "languages": [
        "cpp",
        "dockerfile",
        "dotnet",
        "elixir",
        "golang",
        "helm",
        "java",
        "javascript",
        "kubernetes",
        "linux",
        "php",
        "python",
        "ruby",
        "scala",
        "swift",
        "terraform"
      ],
      "projects":[
          f"{projectId}"
      ],
      "severity": [
        "high",
        "medium",
        "low",
        "none"
      ],
      "depStatus": ""
    }
  }
    response = requests.post(f"https://api.snyk.io/api/v1/org/{orgId}/licenses",
                data= body,
                headers={'Content-type': 'application/json; charset=utf-8', 'Authorization': f'token {token}'},)
    
    json_response = response.json()

    return json_response

def closed_github_issues_for_fixed_snyk_issues(snyk_issues: List):
    pass

def build_projects_with_issues_from_snyk_projects(snyk_projects: List):
    projects_with_issues: List[ProjectIssues] = []

    for ready_project in snyk_projects:
        aggregated_issues = get_snyk_project_issues(g['snyk_client'], g['snyk_org'], ready_project['id'])   
        projects_with_issues.append(
            ProjectIssues(
                ready_project,
                aggregated_issues
            )
        )
    return projects_with_issues

def get_project_from_gh_issue(gh_issue: IssueAndMetadata):
    project_name_from_gh_issue = '/'.join(gh_issue.issue_metadata[METADATA_KEY_ID].split('/')[:-1])
    #print(f"{project_name_from_gh_issue=}")
    for project in g['snyk_open_projects']:
        project_name_from_snyk = project['name'].split(':')[1]
        #print(f"{project_name_from_snyk=}")
        if project_name_from_gh_issue == project_name_from_snyk:
            return project
    
    return None

def create_github_issues_for_snyk_projects_with_issues(snyk_projects_with_issues: List):
    for ready_project in snyk_projects_with_issues:
        #print(f"{ready_project=}")
        #if wait_for_snyk_test(project['lastTestedDate'], g['retry'], g['delay']):
        #issues = get_snyk_project_issues(g['snyk_client'], g['snyk_org'], ready_project.project['id'])
        manifest_name = ready_project.project['name'].split(":")[1]
        #print(f"{issues=}")
        for issue in ready_project.issues['issues']:
            #print(f"f{issue=}")
            snyk_unique_issue_id = issue['id']
            snyk_title = issue['issueData']['title']
            snyk_severity = issue['issueData']['severity']
            snyk_description = issue['issueData']['description']
            snyk_package_name = issue['pkgName']
            snyk_package_version = issue['pkgVersions']

            try:
                snyk_cve = issue['issueData']['identifiers']['CVE'][0]
            except:
                snyk_cve = "No CVE"
                #typer.echo("Issue does not have a CVE")

            try:
                snyk_cwe = "No CWE"
                snyk_cwe = issue['issueData']['identifiers']['CWE'][0]

            except:
                pass
                #typer.echo("Issue does not have a CWE")                

            snyk_issue_id_for_gh = f"{manifest_name}/{snyk_unique_issue_id}"
            print(f" - {snyk_issue_id_for_gh=}, ", end ="")

            title = f"{snyk_cve} - {snyk_severity} detected in {snyk_package_name}{snyk_package_version}"
           
            body = (
                f"Package Name: {snyk_package_name} <br/>"
                f"Package Version: {snyk_package_version} <br/>"
                f"Package Manager: {ready_project.project['type']} <br/>"
                f"Target File: {manifest_name} <br/>"
                f"Severity Level: {snyk_severity} <br/> "
                f"Snyk ID: {snyk_unique_issue_id} <br/> "
                f"Snyk CVE: {snyk_cve} <br/> "
                f"Snyk CWE: {snyk_cwe} <br/> "
                f"Link to issue in Snyk: {ready_project.project['browseUrl']} <br/> <br/>"
                f"Snyk Description: {snyk_description} <br/> "
            )

            gh_issue_exists = snyk_issue_id_for_gh in \
                [x.issue_metadata['id'] for x in g['repo_open_issues'] if x.issue_metadata is not None]

            if gh_issue_exists:
                print(f"already exists (skip)")
                pass
            else:
                print(f"does not exist (create)")
                g['github_client'].create_issue_with_metadata(
                repo_full_name=g['repo_full_name'],
                metadata_prefix=METADATA_PREFIX,
                metadata_key=METADATA_KEY_ID,
                metadata_value=snyk_issue_id_for_gh,
                title=title,
                body=body,
                #labels=labels
                )
                time.sleep(3)

if __name__ == "__main__":
    app()
