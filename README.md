# HelloID-Conn-SA-Full-Google-GroupCreate

<!-- Description -->
## Description
This HelloID Service Automation Delegated Form provides Google group creation functionality. The following options are available:
 1. Enter group name, description and email address
 2. New Google group is created after confirmation
 
<!-- TABLE OF CONTENTS -->
## Table of Contents
* [Description](#description)
* [All-in-one PowerShell setup script](#all-in-one-powershell-setup-script)
  * [Getting started](#getting-started)
* [Post-setup configuration](#post-setup-configuration)
* [Manual resources](#manual-resources)


## All-in-one PowerShell setup script
The PowerShell script "createform.ps1" contains a complete PowerShell script using the HelloID API to create the complete Form including user defined variables, tasks and data sources.

 _Please note that this script asumes none of the required resources do exists within HelloID. The script does not contain versioning or source control_


### Getting started
Please follow the documentation steps on [HelloID Docs](https://docs.helloid.com/hc/en-us/articles/360017556559-Service-automation-GitHub-resources) in order to setup and run the All-in one Powershell Script in your own environment.

 
## Post-setup configuration
After the all-in-one PowerShell script has run and created all the required resources. The following items need to be configured according to your own environment
 1. Update the following [user defined variables](https://docs.helloid.com/hc/en-us/articles/360014169933-How-to-Create-and-Manage-User-Defined-Variables)
<table>
  <tr><td><strong>Variable name</strong></td><td><strong>Example value</strong></td><td><strong>Description</strong></td></tr>
  <tr><td>GoogleClientId</td><td>234234234-rp1ein8ov06sa39oind1n97ikp7nhnggd.apps.googleusercontent.com</td><td>API Client Id</td></tr>
  <tr><td>GoogleClientSecret</td><td>a4VHs9UAFUWPjqeDdzpz6GtE</td><td>API Client Id</td></tr>
  <tr><td>GoogleRedirectUri</td><td>http://localhost/oauth2callback</td><td>API Redirect Uri</td></tr>
  <tr><td>GoogleClientId</td><td>1//06NtAZwSV9F7lCgYIARAAGAYSNwF-L9Iri46v1OUghMEAjMbHCLoRorMgpQEjfuDoqXOFbWcfdsM3hmh76ahF3PQyHXatdIKwxlo</td><td>API Refresh Token</td></tr>
</table>

## Manual resources
This Delegated Form uses the following resources in order to run

### Delegated form task 'google-group-create'
This delegated form task will create the configured new Google group.

# HelloID Docs
The official HelloID documentation can be found at: https://docs.helloid.com/
