# HelloID-Conn-SA-Sync-ActiveDirectory-Groupmemberships-To-SelfService-Productassignments
Synchronizes AD groupmemberships to HelloID Self service productassignments

<a href="https://github.com/Tools4everBV/HelloID-Conn-SA-Sync-ActiveDirectory-Groupmemberships-To-SelfService-Productassignments/network/members"><img src="https://img.shields.io/github/forks/Tools4everBV/HelloID-Conn-SA-Sync-ActiveDirectory-Groupmemberships-To-SelfService-Productassignments" alt="Forks Badge"/></a>
<a href="https://github.com/Tools4everBV/HelloID-Conn-SA-Sync-ActiveDirectory-Groupmemberships-To-SelfService-Productassignments/pulls"><img src="https://img.shields.io/github/issues-pr/Tools4everBV/HelloID-Conn-SA-Sync-ActiveDirectory-Groupmemberships-To-SelfService-Productassignments" alt="Pull Requests Badge"/></a>
<a href="https://github.com/Tools4everBV/HelloID-Conn-SA-Sync-ActiveDirectory-Groupmemberships-To-SelfService-Productassignments/issues"><img src="https://img.shields.io/github/issues/Tools4everBV/HelloID-Conn-SA-Sync-ActiveDirectory-Groupmemberships-To-SelfService-Productassignments" alt="Issues Badge"/></a>
<a href="https://github.com/Tools4everBV/HelloID-Conn-SA-Sync-ActiveDirectory-Groupmemberships-To-SelfService-Productassignments/graphs/contributors"><img alt="GitHub contributors" src="https://img.shields.io/github/contributors/Tools4everBV/HelloID-Conn-SA-Sync-ActiveDirectory-Groupmemberships-To-SelfService-Productassignments?color=2b9348"></a>


| :information_source: Information |
|:---------------------------|
| This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements.       |

## Table of Contents
- [HelloID-Conn-SA-Sync-ActiveDirectory-Groupmemberships-To-SelfService-Productassignments](#helloid-conn-sa-sync-activedirectory-groupmemberships-to-selfservice-productassignments)
  - [Table of Contents](#table-of-contents)
  - [Requirements](#requirements)
  - [Introduction](#introduction)
      - [Create an API key and secret](#create-an-api-key-and-secret)
    - [Synchronization settings](#synchronization-settings)
  - [Remarks](#remarks)
  - [Getting help](#getting-help)
  - [HelloID Docs](#helloid-docs)

## Requirements
- Make sure you have Windows PowerShell 5.1 installed on the server where the HelloID agent and Service Automation agent are running.
- Make sure you have installed the PowerShell [ActiveDirectory](https://learn.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps) module.
- Make sure the sychronization is configured to meet your requirements.

## Introduction

By using this connector, you will have the ability to create and remove HelloID SelfService Productassignments based on groupmemberships in your local Active Directory.

The products will be assigned to a user when they are already a member of the group that the product would make them member of. This way the product can be returned to revoke the groupmembership without having to first request all the products "you already have".

And vice versa for the removing of the productassignments. The products will be returned from a user when they are already no longer a member of the group that the product would make them member of. This way the product can be requested again without having to first return all the products "you already no longer have".

This is intended for scenarios where the groupmemberships are managed by other sources (e.g. manual actions or Provisioning) than the HelloID products to keep this in sync. This groupmembership sync is desinged to work in combination with the [ActiveDirectory Groups to Products Sync](https://github.com/Tools4everBV/HelloID-Conn-SA-Sync-ActiveDirectory-Groups-To-SelfService-Products).

#### Create an API key and secret

1. Go to the `Manage portal > Security > API` section.
2. Click on the `Add Api key` button to create a new API key.
3. Optionally, you can add a note that will describe the purpose of this API key
4. Optionally, you can restrict the IP addresses from which this API key can be used.
5. Click on the `Save` button to save the API key.
6. Go to the `Manage portal > Automation > Variable library` section and confim that the auto variables specified in the [connection settings](#connection-settings) are available.

### Synchronization settings

| Variable name | Description   | Notes |
| ------------- | -----------   | ----- |
| $portalBaseUrl    | String value of HelloID Base Url  | (Default Global Variable) |
| $portalApiKey | String value of HelloID Api Key   | (Default Global Variable) |
| $portalApiSecret  | String value of HelloID Api Secret    | (Default Global Variable) |
| $ADGroupsFilter   | String value of filter of which AD groups to include   | Optional, when no filter is provided ($ADGroupsFilter = "*"), all groups will be queried  |
| $ADGroupsOUs  | Array of string values of which AD OUs to include in search for groups | Optional, when no OUs are provided ($ADGroupsOUs = @()), all ous will be queried  |
| $ProductSkuPrefix | String value of prefix filter of which HelloID Self service Products to include    | Optional, when no SkuPrefix is provided ($ProductSkuPrefix = $null), all products will be queried |
| $PowerShellActionName | String value of name of the PowerShell action that grants the AD user to the Ad group | The default value ("Add-ADUserToADGroup") is set to match the value from the [ActiveDirectory Groups to Products Sync](https://github.com/Tools4everBV/HelloID-Conn-SA-Sync-ActiveDirectory-Groups-To-SelfService-Products)   |
| $PowerShellActionVariableCorrelationProperty  | String value of name of the property of HelloID Self service Product action variables to match to AD Groups (name of the variable of the PowerShell action that contains the group) | The default value ("Group") is set to match the value from the [ActiveDirectory Groups to Products Sync](https://github.com/Tools4everBV/HelloID-Conn-SA-Sync-ActiveDirectory-Groups-To-SelfService-Products), where Group is set as the variable name for the group for the Product actions. If your products are from a different source, change this accordingly (e.g. GroupSID)   |
| $adGroupCorrelationProperty   | String value of name of the property of AD groups to match Groups in HelloID Self service Product actions (the group) | The default value ("samAccountName") is set to match the value from the [ActiveDirectory Groups to Products Sync](https://github.com/Tools4everBV/HelloID-Conn-SA-Sync-ActiveDirectory-Groups-To-SelfService-Products), where the AD group SamAccountName  as the Group value for the Product actions. If your products are from a different source, change this accordingly (e.g. SID)   |
| $adUserCorrelationProperty    | String value of name of the property of AD users to match to HelloID users    | The default value ("UserPrincipalName") is set to match the value from the [ActiveDirectory Groups to Products Sync](https://docs.helloid.com/en/access-management/directory-sync/active-directory-sync.html), where the AD user UserPrincipalName is set to the HelloID User username. If your users are from a different source, change this accordingly  |
| $helloIDUserCorrelationProperty   | String value of name of the property of HelloID users to match to AD users    | The default value ("username") is set to match the value from the [ActiveDirectory Groups to Products Sync](https://docs.helloid.com/en/access-management/directory-sync/active-directory-sync.html), where the AD user UserPrincipalName is set to the HelloID User username. If your users are from a different source, change this accordingly   |

## Remarks
- The Productassignments are granted and revoked. Make sure your configuration is correct to avoid unwanted revokes
- This groupmembership sync is designed to work in combination with the [ActiveDirectory Groups to Products Sync](https://github.com/Tools4everBV/HelloID-Conn-SA-Sync-ActiveDirectory-Groups-To-SelfService-Products). If your products are from a different source, this sync task might not work and needs changes accordingly.

## Getting help
> _For more information on how to configure a HelloID PowerShell scheduled task, please refer to our [documentation](https://docs.helloid.com/hc/en-us/articles/115003253294-Create-Custom-Scheduled-Tasks) pages_

> _If you need help, feel free to ask questions on our [forum](https://forum.helloid.com)_

## HelloID Docs
The official HelloID documentation can be found at: https://docs.helloid.com/