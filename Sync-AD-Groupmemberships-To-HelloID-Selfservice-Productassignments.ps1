#####################################################
# HelloID-SA-Sync-AD-Groupmemberships-To-HelloID-Selfservice-Productassignments
#
# Version: 1.0.0
#####################################################
$VerbosePreference = "SilentlyContinue"
$informationPreference = "Continue"
$WarningPreference = "Continue"

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

# Set to false to acutally perform actions - Only run as DryRun when testing/troubleshooting!
$dryRun = $false
# Set to true to log each individual action - May cause lots of logging, so use with cause, Only run testing/troubleshooting!
$verboseLogging = $false

# Make sure to create the Global variables defined below in HelloID
#HelloID Connection Configuration
# $script:PortalBaseUrl = "" # Set from Global Variable
# $portalApiKey ="" # Set from Global Variable
# $portalApiSecret = "" # Set from Global Variable

#AD Connection Configuration
$ADGroupsFilter = "name -like `"App-*`" -or name -like `"*-App`"" # Optional, when no filter is provided ($ADGroupsFilter = "*"), all groups will be queried
$ADGroupsOUs = @("OU=Applications,OU=Groups,OU=Resources,DC=enyoi,DC=org") # Optional, when no OUs are provided ($ADGroupsOUs = @()), all ous will be queried

#HelloID Self service Product Configuration
$ProductSkuPrefix = 'ADGRP' # Optional, when no SkuPrefix is provided ($ProductSkuPrefix = $null), all products will be queried
$PowerShellActionName = "Add-ADUserToADGroup" # Define the name of the PowerShell action

#Correlation Configuration
$PowerShellActionVariableCorrelationProperty = "Group" # The name of the property of HelloID Self service Product action variables to match to AD Groups (name of the variable of the PowerShell action that contains the group)
$adGroupCorrelationProperty = "samAccountName" # The name of the property of AD groups to match Groups in HelloID Self service Product actions (the group)
$adUserCorrelationProperty = "SID" # The name of the property of AD users to match to HelloID users
$helloIDUserCorrelationProperty = "immutableId" # The name of the property of HelloID users to match to AD users

#region functions
function Resolve-HTTPError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            FullyQualifiedErrorId = $ErrorObject.FullyQualifiedErrorId
            MyCommand             = $ErrorObject.InvocationInfo.MyCommand
            RequestUri            = $ErrorObject.TargetObject.RequestUri
            ScriptStackTrace      = $ErrorObject.ScriptStackTrace
            ErrorMessage          = ""
        }

        if ($ErrorObject.Exception.GetType().FullName -eq "Microsoft.PowerShell.Commands.HttpResponseException") {
            # $httpErrorObj.ErrorMessage = $ErrorObject.ErrorDetails.Message # Does not show the correct error message for the Raet IAM API calls
            $httpErrorObj.ErrorMessage = $ErrorObject.Exception.Message

        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq "System.Net.WebException") {
            $httpErrorObj.ErrorMessage = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
        }

        Write-Output $httpErrorObj
    }
}

function Get-ErrorMessage {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $errorMessage = [PSCustomObject]@{
            VerboseErrorMessage = $null
            AuditErrorMessage   = $null
        }

        if ( $($ErrorObject.Exception.GetType().FullName -eq "Microsoft.PowerShell.Commands.HttpResponseException") -or $($ErrorObject.Exception.GetType().FullName -eq "System.Net.WebException")) {
            $httpErrorObject = Resolve-HTTPError -Error $ErrorObject

            $errorMessage.VerboseErrorMessage = $httpErrorObject.ErrorMessage

            $errorMessage.AuditErrorMessage = $httpErrorObject.ErrorMessage
        }

        # If error message empty, fall back on $ex.Exception.Message
        if ([String]::IsNullOrEmpty($errorMessage.VerboseErrorMessage)) {
            $errorMessage.VerboseErrorMessage = $ErrorObject.Exception.Message
        }
        if ([String]::IsNullOrEmpty($errorMessage.AuditErrorMessage)) {
            $errorMessage.AuditErrorMessage = $ErrorObject.Exception.Message
        }

        Write-Output $errorMessage
    }
}

function Invoke-HIDRestmethod {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Method,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Uri,

        [object]
        $Body,

        [Parameter(Mandatory = $false)]
        $PageSize,

        [string]
        $ContentType = "application/json"
    )

    try {
        Write-Verbose "Switching to TLS 1.2"
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

        Write-Verbose "Setting authorization headers"
        $apiKeySecret = "$($portalApiKey):$($portalApiSecret)"
        $base64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($apiKeySecret))
        $headers = [System.Collections.Generic.Dictionary[[String], [String]]]::new()
        $headers.Add("Authorization", "Basic $base64")
        $headers.Add("Content-Type", $ContentType)
        $headers.Add("Accept", $ContentType)

        $splatParams = @{
            Uri         = "$($script:PortalBaseUrl)/api/v1/$($Uri)"
            Headers     = $headers
            Method      = $Method
            ErrorAction = "Stop"
        }
        
        if (-not[String]::IsNullOrEmpty($PageSize)) {
            $data = [System.Collections.ArrayList]@()

            $skip = 0
            $take = $PageSize
            Do {
                $splatParams["Uri"] = "$($script:PortalBaseUrl)/api/v1/$($Uri)?skip=$($skip)&take=$($take)"

                Write-Verbose "Invoking [$Method] request to [$Uri]"
                $response = $null
                $response = Invoke-RestMethod @splatParams
                if (($response.PsObject.Properties.Match("pageData") | Measure-Object).Count -gt 0) {
                    $dataset = $response.pageData
                }
                else {
                    $dataset = $response
                }

                if ($dataset -is [array]) {
                    [void]$data.AddRange($dataset)
                }
                else {
                    [void]$data.Add($dataset)
                }
            
                $skip += $take
            }until(($dataset | Measure-Object).Count -ne $take)

            return $data
        }
        else {
            if ($Body) {
                Write-Verbose "Adding body to request"
                $splatParams["Body"] = ([System.Text.Encoding]::UTF8.GetBytes($body))
            }

            Write-Verbose "Invoking [$Method] request to [$Uri]"
            $response = $null
            $response = Invoke-RestMethod @splatParams

            return $response
        }

    }
    catch {
        throw $_
    }
}

#endregion functions

#region script
Hid-Write-Status -Event Information -Message "Starting synchronization of Active Directory groupmemberships to HelloID Self service Productassignments"
Hid-Write-Status -Event Information -Message "------[HelloID]------"
try {
    # if ($verboseLogging -eq $true) {
    #     Hid-Write-Status -Event Information -Message "Querying Self service product actions from HelloID"
    # }

    $splatParams = @{
        Method   = "GET"
        Uri      = "selfservice/actions"
        PageSize = 1000
    }
    $helloIDSelfServiceProductActions = Invoke-HIDRestMethod @splatParams

    # Filter for specified actions
    $helloIDSelfServiceProductActionsInScope = [System.Collections.ArrayList]@()
    $PowerShellActionGroupsInScope = [System.Collections.ArrayList]@()
    foreach ($helloIDSelfServiceProductAction in $helloIDSelfServiceProductActions | Where-Object { $_.name -eq "$PowerShellActionName" -and $_.executionEntry -eq "powershell-script" -and $_.executionType -eq "native" -and $_.executeOnState -ne "0" -and $_.executeOnState -ne $null }) {
        foreach ($variable in $helloIDSelfServiceProductAction.variables) {
            if ( $variable.Name -eq $PowerShellActionVariableCorrelationProperty -and $variable.Value -notlike "{{*}}") {
                if ($helloIDSelfServiceProductAction -notin $helloIDSelfServiceProductActionsInScope) {
                    [void]$helloIDSelfServiceProductActionsInScope.Add($helloIDSelfServiceProductAction)
                }

                if (-not[string]::IsNullOrEmpty($variable.Value) -and $variable.Value -notin $PowerShellActionGroupsInScope) {
                    [void]$PowerShellActionGroupsInScope.Add($variable.Value)
                }
            }
        }
    }
    
    Hid-Write-Status -Event Success -Message "Successfully queried Self service product actions from HelloID (after filtering for specified custom powershell actions). Result count: $(($helloIDSelfServiceProductActionsInScope | Measure-Object).Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying Self service product actions from HelloID. Error Message: $($errorMessage.AuditErrorMessage)"
}

try {
    # if ($verboseLogging -eq $true) {
    #     Hid-Write-Status -Event Information -Message "Querying Self service products from HelloID"
    # }

    $splatParams = @{
        Method = "GET"
        Uri    = "selfservice/products"
    }
    $helloIDSelfServiceProducts = Invoke-HIDRestMethod @splatParams

    # Filter for products with specified Sku Prefix
    if (-not[String]::IsNullOrEmpty($ProductSkuPrefix)) {
        $helloIDSelfServiceProductsInScope = $null
        $helloIDSelfServiceProductsInScope = $helloIDSelfServiceProducts | Where-Object { $_.code -like "$ProductSkuPrefix*" }
    }
    else {
        $helloIDSelfServiceProductsInScope = $null
        $helloIDSelfServiceProductsInScope = $helloIDSelfServiceProducts
    }

    # Filter for products with specified actions
    $helloIDSelfServiceProductsInScope = $helloIDSelfServiceProductsInScope | Where-Object { $_.selfServiceProductGUID -in $helloIDSelfServiceProductActionsInScope.objectGUID }

    Hid-Write-Status -Event Success -Message "Successfully queried Self service products from HelloID (after filtering for products with specified actions only). Result count: $(($helloIDSelfServiceProductsInScope | Measure-Object).Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying Self service products from HelloID. Error Message: $($errorMessage.AuditErrorMessage)"
}

try {
    # if ($verboseLogging -eq $true) {
    #     Hid-Write-Status -Event Information -Message "Querying  Self service Productassignments from HelloID"
    # }

    $splatParams = @{
        Method   = "GET"
        Uri      = "product-assignment"
        PageSize = 1000
    }
    $helloIDSelfServiceProductassignments = Invoke-HIDRestMethod @splatParams

    # Filter for for productassignments of specified products
    $helloIDSelfServiceProductassignmentsInScope = $null
    $helloIDSelfServiceProductassignmentsInScope = $helloIDSelfServiceProductassignments | Where-Object { $_.productGuid -in $helloIDSelfServiceProductsInScope.selfServiceProductGUID }

    $helloIDSelfServiceProductassignmentsInScopeGrouped = $helloIDSelfServiceProductassignmentsInScope | Group-Object -Property productGuid -AsHashTable -AsString
    Hid-Write-Status -Event Success -Message "Successfully queried Self service Productassignments from HelloID (after filtering for productassignments of specified products only). Result count: $(($helloIDSelfServiceProductassignmentsInScope | Measure-Object).Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying Self service Productassignments from HelloID. Error Message: $($errorMessage.AuditErrorMessage)"
}

try {
    # if ($verboseLogging -eq $true) {
    #     Hid-Write-Status -Event Information -Message "Querying Users from HelloID"
    # }

    $splatParams = @{
        Method   = "GET"
        Uri      = "users"
        PageSize = 1000
    }
    $helloIDUsers = Invoke-HIDRestMethod @splatParams

    $helloIDUsersInScope = $null
    $helloIDUsersInScope = $helloIDUsers

    $helloIDUsersInScopeGrouped = $helloIDUsersInScope | Group-Object -Property $helloIDUserCorrelationProperty -AsHashTable -AsString
    Hid-Write-Status -Event Success -Message "Successfully queried Users from HelloID. Result count: $(($helloIDUsersInScope | Measure-Object).Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying Users from HelloID. Error Message: $($errorMessage.AuditErrorMessage)"
}

Hid-Write-Status -Event Information -Message "------[Active Directory]-----------"  
try {
    $moduleName = "ActiveDirectory"
    $importModule = Import-Module -Name $moduleName -ErrorAction Stop
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error importing module [$moduleName]. Error Message: $($errorMessage.AuditErrorMessage)"
}

# Get AD Groups
try {  
    $properties = @(
        $adGroupCorrelationProperty
        , "SID"
        
    )

    $adQuerySplatParams = @{
        Filter     = $ADGroupsFilter
        Properties = $properties
    }

    if ([String]::IsNullOrEmpty($ADGroupsOUs)) {
        if ($verboseLogging -eq $true) {
            Hid-Write-Status -Event Information -Message "Querying AD groups that match filter [$($adQuerySplatParams.Filter)]"
        }
        $adGroups = Get-ADGroup @adQuerySplatParams | Select-Object $properties
 
        if ($verboseLogging -eq $true) {
            Hid-Write-Status -Event Success -Message "Successfully queried AD groups that match filter [$($adQuerySplatParams.Filter)]. Result count: $(($adGroups | Measure-Object).Count)"
        }
    }
    else {
        $adGroups = [System.Collections.ArrayList]@()
        foreach ($ADGroupsOU in $ADGroupsOUs) {
            if ($verboseLogging -eq $true) {
                Hid-Write-Status -Event Information -Message "Querying AD groups that match filter [$($adQuerySplatParams.Filter)] in OU [$($ADGroupsOU)]"
            }
            $adGroupsInOU = Get-ADGroup @adQuerySplatParams -SearchBase $ADGroupsOU | Select-Object $properties
            if ($adGroupsInOU -is [array]) {
                [void]$adGroups.AddRange($adGroupsInOU)
            }
            else {
                [void]$adGroups.Add($adGroupsInOU)
            }
            
            if ($verboseLogging -eq $true) {
                Hid-Write-Status -Event Success -Message "Successfully queried AD groups that match filter [$($adQuerySplatParams.Filter)] in OU [$($ADGroupsOU)]. Result count: $(($adGroupsInOU | Measure-Object).Count)"
            }
        }
    }

    # Filter for groups that are in products
    $adGroupsInScope = $null
    $adGroupsInScope = $adGroups | Where-Object { $_.$adGroupCorrelationProperty -in $PowerShellActionGroupsInScope }

    if (($adGroupsInScope.SID | Measure-Object).Count -ge 1) {
        $adGroupsInScope | ForEach-Object {
            # Get value of SID
            $_.SID = $_.SID.Value
        }
    }

    Hid-Write-Status -Event Success -Message "Successfully queried AD groups (after filtering for groups that are in products). Result count: $(($adGroupsInScope | Measure-Object).Count)"

    # Get AD Groupmemberships of groups
    try {
        if ($verboseLogging -eq $true) {
            Hid-Write-Status -Event Information -Message "Enhancing AD groups with members"
        }
        $adGroupsInScope | Add-Member -MemberType NoteProperty -Name "members" -Value $null -Force
        $totalADGroupMembers = 0
        foreach ($adGroup in $adGroupsInScope) {
            try {
                $properties = @(
                    $adUserCorrelationProperty
                    , "distinguishedName"
                    , "objectClass"
                )

                # if ($verboseLogging -eq $true) {
                #     Hid-Write-Status -Event Information -Message "Querying AD groupmembers of group [$($adGroup.SID)]"
                # }
                $adGroupMembers = $null
                $adGroupMembers = Get-ADGroupMember -Identity $adGroup.SID | Select-Object $properties
                
                if (($adGroupMembers.SID | Measure-Object).Count -ge 1) {
                    $adGroupMembers | ForEach-Object {
                        # Get value of SID
                        $_.SID = $_.SID.Value
                    }
                }

                # Filter for user objects
                $adGroupMembers = $adGroupMembers | Where-Object { $_.objectClass -eq "user" }

                # Filter for users that exist in HelloID
                $adGroupMembersInScope = $null
                $adGroupMembersInScope = $adGroupMembers | Where-Object { $_.$adUserCorrelationProperty -in $helloIDUsersInScope.$helloIDUserCorrelationProperty }

                # Set property of AD group with members
                $adGroup.members = $adGroupMembersInScope

                # if ($verboseLogging -eq $true) {
                #     Hid-Write-Status -Event Success -Message "Successfully queried AD groupmembers of group [$($adGroup.SID)] (after filtering for users that exist in HelloID). Result count: $(($adGroupMembersInScope | Measure-Object).Count)"                
                # }

                foreach ($adGroupMember in $adGroupMembers) {
                    $totalADGroupMembers++
                }
            }
            catch {
                $ex = $PSItem
                $errorMessage = Get-ErrorMessage -ErrorObject $ex

                if ($verboseLogging -eq $true) {
                    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"
                    
                    Hid-Write-Status -Event Error -Message "Error querying AD groupmembers of group [$($adGroup.SID)]. Error Message: $($errorMessage.AuditErrorMessage)"
                }
            }
        }

        Hid-Write-Status -Event Success -Message "Successfully enhanced AD groups with members (after filtering for users that exist in HelloID). Result count: $($totalADGroupMembers)"
    }
    catch {
        $ex = $PSItem
        $errorMessage = Get-ErrorMessage -ErrorObject $ex

        Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

        throw "Error querying AD groupmembers. Error Message: $($errorMessage.AuditErrorMessage)"
    }

    $adGroupsGrouped = $adGroups | Group-Object -Property $adGroupCorrelationProperty -AsHashTable -AsString
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying AD groups that match filter [$($adQuerySplatParams.Filter)]. Error Message: $($errorMessage.AuditErrorMessage)"
}

Hid-Write-Status -Event Information -Message "------[Calculations of combined data]------"
# Calculate new and obsolete product assignments
try {
    $newProductAssignmentObjects = [System.Collections.ArrayList]@()
    $obsoleteProductAssignmentObjects = [System.Collections.ArrayList]@()
    $existingProductAssignmentObjects = [System.Collections.ArrayList]@()
    foreach ($product in $helloIDSelfServiceProductsInScope) {
        # if ($verboseLogging -eq $true) {
        #     Hid-Write-Status -Event Information -Message "Calculating new and obsolete product assignments for Product [$($product.name)]"
        # }

        # Get Group from Product Action
        $productActionsInScope = $helloIDSelfServiceProductActionsInScope | Where-Object { $_.objectGUID -eq $product.selfServiceProductGUID }
        $variablesInScope = [PSCustomObject]$productActionsInScope | Select-Object -ExpandProperty variables
        $groupName = [PSCustomObject]$variablesInScope | Where-Object { $_.name -eq "$PowerShellActionVariableCorrelationProperty" } | Select-Object value | Sort-Object value -Unique | Select-Object -ExpandProperty value
        $adGroup = $null
        $adGroup = $adGroupsGrouped[$groupName]
        if (($adGroup | Measure-Object).Count -eq 0) {
            Hid-Write-Status -Event Error -Message "No AD group found with $adGroupCorrelationProperty [$($groupName)] for Product [$($product.name)]"
            continue
        }
        elseif (($adGroup | Measure-Object).Count -gt 1) {
            Hid-Write-Status -Event Error -Message "Multiple AD groups found with $adGroupCorrelationProperty [$($groupName)] for Product [$($product.name)]. Please correct this so the $adGroupCorrelationProperty of the AD group is unique"
            continue
        }

        # Get AD user objects for additional data to match to HelloID user
        $adUsersInScope = $adGroup.members
        
        # Get HelloID user objects to assign to the product
        $productUsersInScope = [System.Collections.ArrayList]@()
        foreach ($adUser in $adUsersInScope) {
            $helloIDUser = $null
            $helloIDUser = $helloIDUsersInScopeGrouped[$adUser.$adUserCorrelationProperty]

            if (($helloIDUser | Measure-Object).Count -eq 0) {
                if ($verboseLogging -eq $true) {
                    Hid-Write-Status -Event Error -Message "No HelloID user found with $helloIDUserCorrelationProperty [$($adUser.$adUserCorrelationProperty)] for AD user [$($adUser.distinguishedName)] for Product [$($product.name)]"
                    continue
                }
            }
            else {
                [void]$productUsersInScope.Add($helloIDUser)
            }
        }

        # Get current product assignments
        $currentProductassignments = $null
        if (($helloIDSelfServiceProductassignmentsInScope | Measure-Object).Count -ge 1) {
            $currentProductassignments = $helloIDSelfServiceProductassignmentsInScopeGrouped[$product.selfServiceProductGUID]
        }

        # Define assignments to grant
        $newProductassignments = $productUsersInScope | Where-Object { $_.userGuid -notin $currentProductassignments.userGuid }
        foreach ($newProductAssignment in $newProductassignments) {
            $newProductAssignmentObject = [PSCustomObject]@{
                productGuid            = "$($product.selfServiceProductGUID)"
                productName            = "$($product.name)"
                userGuid               = "$($newProductAssignment.userGuid)"
                userName               = "$($newProductAssignment.userName)"
                source                 = "SyncADGroupMemberShipsToProductAssignments"
                executeApprovalActions = $false
            }

            [void]$newProductAssignmentObjects.Add($newProductAssignmentObject)
        }

        # Define assignments to revoke
        $obsoleteProductassignments = $currentProductassignments | Where-Object { $_.userGuid -notin $productUsersInScope.userGuid }
        foreach ($obsoleteProductassignment in $obsoleteProductassignments) { 
            $obsoleteProductAssignmentObject = [PSCustomObject]@{
                productGuid            = "$($product.selfServiceProductGUID)"
                productName            = "$($product.name)"
                userGuid               = "$($obsoleteProductassignment.userGuid)"
                userName               = "$($obsoleteProductassignment.userName)"
                source                 = "SyncADGroupMemberShipsToProductAssignments"
                executeApprovalActions = $false
            }
    
            [void]$obsoleteProductAssignmentObjects.Add($obsoleteProductAssignmentObject)
        }

        # Define assignments already existing
        $existingProductassignments = $currentProductassignments | Where-Object { $_.userGuid -in $productUsersInScope.userGuid }
        foreach ($existingProductassignment in $existingProductassignments) { 
            $existingProductAssignmentObject = [PSCustomObject]@{
                productGuid            = "$($product.selfServiceProductGUID)"
                productName            = "$($product.name)"
                userGuid               = "$($existingProductassignment.userGuid)"
                userName               = "$($existingProductassignment.userName)"
                source                 = "SyncADGroupMemberShipsToProductAssignments"
                executeApprovalActions = $false
            }
    
            [void]$existingProductAssignmentObjects.Add($existingProductAssignmentObject)
        }

        # Define total assignments (existing + new assignments)
        $totalProductAssignments = ($(($existingProductAssignmentObjects | Measure-Object).Count) + $(($newProductAssignmentObjects | Measure-Object).Count))
    }
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error calculating new and obsolete product assignments. Error Message: $($errorMessage.AuditErrorMessage)"
}

Hid-Write-Status -Event Information -Message "------[Summary]------"

Hid-Write-Status -Event Information -Message "Total HelloID Self service Product(s) in scope [$(($helloIDSelfServiceProductsInScope | Measure-Object).Count)]"

Hid-Write-Status -Event Information -Message "Total HelloID Self service Productassignment(s) already exist (and won't be changed) [$(($existingProductAssignmentObjects | Measure-Object).Count)]"

Hid-Write-Status -Event Information -Message "Total HelloID Self service Productassignment(s) to grant [$(($newProductAssignmentObjects | Measure-Object).Count)]"

Hid-Write-Status -Event Information -Message "Total HelloID Self service Productassignment(s) to revoke [$(($obsoleteProductAssignmentObjects | Measure-Object).Count)]"

Hid-Write-Status -Event Information -Message "------[Processing]------------------"
try {
    # Grant assignments
    $productAssigmentGrantsSuccess = 0
    $productAssigmentGrantsError = 0
    foreach ($newProductAssignmentObject in $newProductAssignmentObjects) {
        try {
            # if ($verboseLogging -eq $true) {
            #     Hid-Write-Status -Event Information -Message "Granting productassignment for HelloID user [$($newProductAssignmentObject.username) ($($newProductAssignmentObject.userGuid))] to HelloID Self service Product [$($newProductAssignmentObject.productName) ($($newProductAssignmentObject.productGuid))]""
            # }
        
            $body = @{
                userGuid               = "$($newProductAssignmentObject.userGuid)"
                source                 = "$($newProductAssignmentObject.source)"
                executeApprovalActions = $newProductAssignmentObject.executeApprovalActions
            } | ConvertTo-Json

            $splatParams = @{
                Method      = "POST"
                Uri         = "product-assignment/$($newProductAssignmentObject.productGuid)"
                Body        = $body # ([System.Text.Encoding]::UTF8.GetBytes($body))
                ErrorAction = "Stop"
            }
            if ($dryRun -eq $false) {
                $grantProductassignmentToUser = Invoke-HIDRestMethod @splatParams
                if ($verboseLogging -eq $true) {
                    Hid-Write-Status -Event Success -Message "Successfully granted productassignment for HelloID user [$($newProductAssignmentObject.username) ($($newProductAssignmentObject.userGuid))] to HelloID Self service Product [$($newProductAssignmentObject.productName) ($($newProductAssignmentObject.productGuid))]"
                }
                $productAssigmentGrantsSuccess++
            }
            else {
                if ($verboseLogging -eq $true) {
                    Hid-Write-Status -Event Success -Message "DryRun: Would grant productassignment for HelloID user [$($newProductAssignmentObject.username) ($($newProductAssignmentObject.userGuid))] to HelloID Self service Product [$($newProductAssignmentObject.productName) ($($newProductAssignmentObject.productGuid))]"
                }   
            }
        }
        catch {
            $ex = $PSItem
            $errorMessage = Get-ErrorMessage -ErrorObject $ex
        
            Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"
        
            $productAssigmentGrantsError++
            if ($verboseLogging -eq $true) {
                Hid-Write-Status -Event Error -Message "Error granting productassignment for HelloID user [$($newProductAssignmentObject.username) ($($newProductAssignmentObject.userGuid))] to HelloID Self service Product [$($newProductAssignmentObject.productName) ($($newProductAssignmentObject.productGuid))]. Error Message: $($errorMessage.AuditErrorMessage)"
            }
        }
    }
    if ($dryRun -eq $false) {
        if ($productAssigmentGrantsSuccess -ge 1 -or $productAssigmentGrantsError -ge 1) {
            Hid-Write-Status -Event Information -Message "Granted productassignments to HelloID Self service Products. Success: $($productAssigmentGrantsSuccess). Error: $($productAssigmentGrantsError)"
            Hid-Write-Summary -Event Information -Message "Granted productassignments to HelloID Self service Products. Success: $($productAssigmentGrantsSuccess). Error: $($productAssigmentGrantsError)"
        }
    }
    else {
        Hid-Write-Status -Event Warning -Message "DryRun: Would grant [$(($newProductAssignmentObjects | Measure-Object).Count)] productassignments for [$(($newProductAssignmentObjects | Sort-Object -Property productGuid -Unique | Measure-Object).Count)] HelloID Self service Products"
        Hid-Write-Summary -Event Warning "DryRun: Would grant [$(($newProductAssignmentObjects | Measure-Object).Count)] productassignments for [$(($newProductAssignmentObjects | Sort-Object -Property productGuid -Unique | Measure-Object).Count)] HelloID Self service Products"
    }

    # Revoke assignments
    $productAssigmentRevokesSuccess = 0
    $productAssigmentRevokesError = 0
    foreach ($obsoleteProductAssignmentObject in $obsoleteProductAssignmentObjects) { 
        try {
            # if ($verboseLogging -eq $true) {
            #     Hid-Write-Status -Event Information -Message "Revoking productassignment for HelloID user [$($obsoleteProductAssignmentObject.username) ($($obsoleteProductAssignmentObject.userGuid))] to HelloID Self service Product [$($obsoleteProductAssignmentObject.productName) ($($obsoleteProductAssignmentObject.productGuid))]""
            # }
            
            $body = @{
                productGuid            = "$($obsoleteProductAssignmentObject.productGuid)"
                userGuid               = "$($obsoleteProductAssignmentObject.userGuid)"
                executeApprovalActions = $($obsoleteProductAssignmentObject.executeApprovalActions)
            } | ConvertTo-Json

            $splatParams = @{
                Method      = "POST"
                Uri         = "product-assignment/unassign/by-product"
                Body        = $body # ([System.Text.Encoding]::UTF8.GetBytes($body))
                ErrorAction = "Stop"
            }
            if ($dryRun -eq $false) {
                $revokeProductassignmentToUser = Invoke-HIDRestMethod @splatParams
                if ($verboseLogging -eq $true) {
                    Hid-Write-Status -Event Success -Message "Successfully revoked productassignment for HelloID user [$($obsoleteProductAssignmentObject.username) ($($obsoleteProductAssignmentObject.userGuid))] to HelloID Self service Product [$($obsoleteProductAssignmentObject.productName) ($($obsoleteProductAssignmentObject.productGuid))]"
                }
                $productAssigmentRevokesSuccess++
            }
            else {
                if ($verboseLogging -eq $true) {
                    Hid-Write-Status -Event Success -Message "DryRun: Would revoke productassignment for HelloID user [$($obsoleteProductAssignmentObject.username) ($($obsoleteProductAssignmentObject.userGuid))] to HelloID Self service Product [$($obsoleteProductAssignmentObject.productName) ($($obsoleteProductAssignmentObject.productGuid))]"
                }   
            }
        }
        catch {
            $ex = $PSItem
            $errorMessage = Get-ErrorMessage -ErrorObject $ex
            
            Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"
            
            $productAssigmentRevokesError++
            if ($verboseLogging -eq $true) {
                Hid-Write-Status -Event Error -Message "Error revoking productassignment for HelloID user [$($obsoleteProductAssignmentObject.username) ($($obsoleteProductAssignmentObject.userGuid))] to HelloID Self service Product [$($obsoleteProductAssignmentObject.productName) ($($obsoleteProductAssignmentObject.productGuid))]. Error Message: $($errorMessage.AuditErrorMessage)"
            }
        }
    }
    if ($dryRun -eq $false) {
        if ($productAssigmentRevokesSuccess -ge 1 -or $productAssigmentRevokesError -ge 1) {
            Hid-Write-Status -Event Information -Message "Revoked productassignments to HelloID Self service Products. Success: $($productAssigmentRevokesSuccess). Error: $($productAssigmentRevokesError)"
            Hid-Write-Summary -Event Information -Message "Revoked productassignments to HelloID Self service Products. Success: $($productAssigmentRevokesSuccess). Error: $($productAssigmentRevokesError)"
        }
    }
    else {
        Hid-Write-Status -Event Warning -Message "DryRun: Would revoke [$(($obsoleteProductassignmentObjects | Measure-Object).Count)] productassignments for [$(($obsoleteProductassignmentObjects | Sort-Object -Property productGuid -Unique | Measure-Object).Count)] HelloID Self service Products"
        Hid-Write-Status -Event Warning -Message "DryRun: Would revoke [$(($obsoleteProductassignmentObjects | Measure-Object).Count)] productassignments for [$(($obsoleteProductassignmentObjects | Sort-Object -Property productGuid -Unique | Measure-Object).Count)] HelloID Self service Products"
    }

    if ($dryRun -eq $false) {
        Hid-Write-Status -Event Success -Message "Successfully synchronized [$($totalADGroupMembers)] Active Directory groupmemberships to [$totalProductAssignments] HelloID Self service Productassignments for [$(($helloIDSelfServiceProductsInScope | Measure-Object).Count)] HelloID Self service Products"
        Hid-Write-Summary -Event Success -Message "Successfully synchronized [$($totalADGroupMembers)] Active Directory groupmemberships to [$totalProductAssignments] HelloID Self service Productassignments for [$(($helloIDSelfServiceProductsInScope | Measure-Object).Count)] HelloID Self service Products"
    }
    else {
        Hid-Write-Status -Event Success -Message "DryRun: Would synchronize [$($totalADGroupMembers)] Active Directory groupmemberships to [$totalProductAssignments] HelloID Self service Productassignments for [$(($helloIDSelfServiceProductsInScope | Measure-Object).Count)] HelloID Self service Products"
        Hid-Write-Summary -Event Success -Message "DryRun: Would synchronize [$($totalADGroupMembers)] Active Directory groupmemberships to [$totalProductAssignments] HelloID Self service Productassignments for [$(($helloIDSelfServiceProductsInScope | Measure-Object).Count)] HelloID Self service Products"
    }
}
catch {
    Hid-Write-Status -Event Error -Message "Error synchronization of [$($totalADGroupMembers)] Active Directory groupmemberships to [$totalProductAssignments] HelloID Self service Productassignments for [$(($helloIDSelfServiceProductsInScope | Measure-Object).Count)] HelloID Self service Products"
    Hid-Write-Status -Event Error -Message "Error at Line [$($_.InvocationInfo.ScriptLineNumber)]: $($_.InvocationInfo.Line)."
    Hid-Write-Status -Event Error -Message "Exception message: $($_.Exception.Message)"
    Hid-Write-Status -Event Error -Message "Exception details: $($_.errordetails)"
    Hid-Write-Summary -Event Failed -Message "Error synchronization of [$($totalADGroupMembers)] Active Directory groupmemberships to [$totalProductAssignments] HelloID Self service Productassignments for [$(($helloIDSelfServiceProductsInScope | Measure-Object).Count)] HelloID Self service Products"
}
#endregion