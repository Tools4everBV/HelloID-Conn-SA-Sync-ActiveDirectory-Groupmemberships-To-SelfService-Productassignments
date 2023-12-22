#####################################################
# HelloID-Conn-SA-Sync-AD-Groupmemberships-To-HelloID-Productassignments
#
# Version: 1.2.0
#####################################################
# Set to false to acutally perform actions - Only run as DryRun when testing/troubleshooting!
$dryRun = $false
# Set to true to log each individual action - May cause lots of logging, so use with cause, Only run testing/troubleshooting!
$verboseLogging = $false

switch ($verboseLogging) {
    $true { $VerbosePreference = "Continue" }
    $false { $VerbosePreference = "SilentlyContinue" }
}
$informationPreference = "Continue"
$WarningPreference = "Continue"

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

# Make sure to create the Global variables defined below in HelloID
#HelloID Connection Configuration
# $script:PortalBaseUrl = "" # Set from Global Variable
# $portalApiKey = "" # Set from Global Variable
# $portalApiSecret = "" # Set from Global Variable

# Active Directory Connection Configuration
$ADGroupsFilter = "name -like `"App-*`" -or name -like `"*-App`"" # Optional, when no filter is provided ($ADGroupsFilter = "*"), all groups will be queried
$ADGroupsOUs = @("OU=Applications,OU=Groups,OU=Resources,DC=enyoi,DC=org") # Optional, when no OUs are provided ($ADGroupsOUs = @()), all ous will be queried

#HelloID Self service Product Configuration
$ProductSkuPrefix = "APPGRP"
$PowerShellActionName = "Add-ADUserToADGroup" # Define the name of the PowerShell action

#Correlation Configuration
# The name of the property of HelloID users to match to AD users - value has to match the value of the propertye specified in $adUserCorrelationProperty
$helloIDUserCorrelationProperty = "username"
# The name of the property of AD users to match to HelloID users - value has to match the value of the propertye specified in $helloIDUserCorrelationProperty
$adUserCorrelationProperty = "userPrincipalName"

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

        $splatWebRequest = @{
            Uri             = "$($script:PortalBaseUrl)/api/v1/$($Uri)"
            Headers         = $headers
            Method          = $Method
            UseBasicParsing = $true
            ErrorAction     = "Stop"
        }
        
        if (-not[String]::IsNullOrEmpty($PageSize)) {
            $data = [System.Collections.ArrayList]@()

            $skip = 0
            $take = $PageSize
            Do {
                $splatWebRequest["Uri"] = "$($script:PortalBaseUrl)/api/v1/$($Uri)?skip=$($skip)&take=$($take)"

                Write-Verbose "Invoking [$Method] request to [$Uri]"
                $response = $null
                $response = Invoke-RestMethod @splatWebRequest -Verbose:$false
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
                $splatWebRequest["Body"] = ([System.Text.Encoding]::UTF8.GetBytes($body))
            }

            Write-Verbose "Invoking [$Method] request to [$Uri]"
            $response = $null
            $response = Invoke-RestMethod @splatWebRequest -Verbose:$false

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
#region Get HelloID Products
try {
    Write-Verbose "Querying Self service products from HelloID"

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

    Hid-Write-Status -Event Success -Message "Successfully queried Self service products from HelloID (after filtering for products with specified sku prefix only). Result count: $(($helloIDSelfServiceProductsInScope | Measure-Object).Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying Self service products from HelloID. Error Message: $($errorMessage.AuditErrorMessage)"
}
#endregion Get HelloID Products

#region Get HelloID Users
try {
    Write-Verbose "Querying Users from HelloID"

    $splatWebRequest = @{
        Method   = "GET"
        Uri      = "users"
        PageSize = 1000
    }
    $helloIDUsers = Invoke-HIDRestMethod @splatWebRequest

    # $helloIDUsersGroupedOnUserName = $helloIDUsers | Group-Object -Property "userName" -AsHashTable -AsString
    # $helloIDUsersGroupedOnUserGUID = $helloIDUsers | Group-Object -Property "userGUID" -AsHashTable -AsString
    $helloIDUsersGrouped = $helloIDUsers | Group-Object -Property $helloIDUserCorrelationProperty -AsHashTable -AsString

    Hid-Write-Status -Event Success -Message "Successfully queried Users from HelloID. Result count: $(($helloIDUsers | Measure-Object).Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying Users from HelloID. Error Message: $($errorMessage.AuditErrorMessage)"
}
#endregion Get HelloID Users

#region Get actions of Product
try {
    [System.Collections.ArrayList]$helloIDSelfServiceProductsInScopeWithActions = @()
    Write-Verbose "Querying HelloID Self service Products with Actions"
    foreach ($helloIDSelfServiceProductInScope in $helloIDSelfServiceProductsInScope) {
        #region Get objects with membership to AD group
        try {
            $helloIDSelfServiceProductInScopeWithActionsObject = [PSCustomObject]@{
                productId   = $helloIDSelfServiceProductInScope.selfServiceProductGUID
                name        = $helloIDSelfServiceProductInScope.name
                description = $helloIDSelfServiceProductInScope.description
                code        = $helloIDSelfServiceProductInScope.code
                actions     = [System.Collections.ArrayList]@()
            }

            Write-Verbose "Querying actions of Product [$($helloIDSelfServiceProductInScope.selfServiceProductGUID)]"

            $splatParams = @{
                Method = "GET"
                Uri    = "products/$($helloIDSelfServiceProductInScope.selfServiceProductGUID)"
            }
            $helloIDSelfServiceProduct = Invoke-HIDRestMethod @splatParams

            # Add actions of all "grant" states
            $helloIDSelfServiceProductActions = $helloIDSelfServiceProduct.onRequest + $helloIDSelfServiceProduct.onApprove
            foreach ($helloIDSelfServiceProductAction in $helloIDSelfServiceProductActions) {
                $helloIDSelfServiceProductActionObject = [PSCustomObject]@{
                    actionGUID = $helloIDSelfServiceProductAction.actionGUID
                    name       = $helloIDSelfServiceProductAction.name
                    objectGUID = $helloIDSelfServiceProductAction.objectGUID
                }

                [void]$helloIDSelfServiceProductInScopeWithActionsObject.actions.Add($helloIDSelfServiceProductActionObject)
            }

            [void]$helloIDSelfServiceProductsInScopeWithActions.Add($helloIDSelfServiceProductInScopeWithActionsObject)

            if ($verboseLogging -eq $true) {
                Hid-Write-Status -Event Success "Successfully queried actions of Product [$($helloIDSelfServiceProductInScope.selfServiceProductGUID)]. Result count: $(($helloIDSelfServiceProduct.actions | Measure-Object).Count)"
            }
        }
        catch {
            $ex = $PSItem
            $errorMessage = Get-ErrorMessage -ErrorObject $ex
        
            Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"
        
            throw "Error querying actions of Product [$($helloIDSelfServiceProductInScope.productId)]. Error Message: $($errorMessage.AuditErrorMessage)"
        }
        #endregion Get objects with with membership to AD group
    }

    # Filter for products with specified actions
    $helloIDSelfServiceProductsInScopeWithActionsInScope = $helloIDSelfServiceProductsInScopeWithActions | Where-Object { $PowerShellActionName -in $_.actions.name }

    Hid-Write-Status -Event Success -Message "Successfully queried HelloID Self service Products with Actions (after filtering for products with specified action only). Result count: $(($helloIDSelfServiceProductsInScopeWithActionsInScope.actions | Measure-Object).Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying HelloID Self service Products with Actions. Error Message: $($errorMessage.AuditErrorMessage)"
}
#endregion Get actions of Product

#region Get HelloID Productassignments
try {
    Write-Verbose "Querying  Self service Productassignments from HelloID"

    $splatParams = @{
        Method   = "GET"
        Uri      = "product-assignment"
        PageSize = 1000
    }
    $helloIDSelfServiceProductassignments = Invoke-HIDRestMethod @splatParams

    # Filter for for productassignments of specified products
    $helloIDSelfServiceProductassignmentsInScope = $null
    $helloIDSelfServiceProductassignmentsInScope = $helloIDSelfServiceProductassignments | Where-Object { $_.productGuid -in $helloIDSelfServiceProductsInScopeWithActionsInScope.productId }

    $helloIDSelfServiceProductassignmentsInScopeGrouped = $helloIDSelfServiceProductassignmentsInScope | Group-Object -Property productGuid -AsHashTable -AsString
    Hid-Write-Status -Event Success -Message "Successfully queried Self service Productassignments from HelloID (after filtering for productassignments of specified products only). Result count: $(($helloIDSelfServiceProductassignmentsInScope | Measure-Object).Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying Self service Productassignments from HelloID. Error Message: $($errorMessage.AuditErrorMessage)"
}
#endregion Get HelloID Productassignments

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

#region Get AD Groups
try {  
    $properties = @(
        "objectGuid"
        , "distinguishedName"
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

    Hid-Write-Status -Event Success -Message "Successfully queried AD groups. Result count: $(($adGroups | Measure-Object).Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying AD groups that match filter [$($adQuerySplatParams.Filter)]. Error Message: $($errorMessage.AuditErrorMessage)"
}
#region Get AD Groups

#region Get members of AD Groups
try {
    [System.Collections.ArrayList]$adGroupsWithMembers = @()
    Write-Verbose "Querying AD Groups with members"
    foreach ($adGroup in $adGroups) {       
        try {            
            $adGroupWithMembersObject = [PSCustomObject]@{
                Name       = $adGroup.Name
                ObjectGUID = $adGroup.objectGUID
                Users      = [System.Collections.ArrayList]@()
            }

            Write-Verbose "Querying Members of Group [$($adGroup.Name)]"

            $properties = @(
                $adUserCorrelationProperty
                , "name"
                , "distinguishedName"
                , "objectClass"
            )

            $adGroupMembers = $null
            $adGroupMembers = Get-ADObject -LDAPFilter "(memberOf=$($adGroup.distinguishedName))" -Properties $properties

            # Filter for user objects
            $adGroupMembers = $adGroupMembers | Where-Object { $_.objectClass -eq "user" }

            foreach ($adGroupMember in $adGroupMembers) {
                $userMemberOfObject = [PSCustomObject]@{
                    Name                       = $adGroupMember.Name
                    ObjectGUID                 = $adGroupMember.objectGUID
                    $adUserCorrelationProperty = $adGroupMember.$adUserCorrelationProperty
                }

                [void]$adGroupWithMembersObject.Users.Add($userMemberOfObject)
            }

            [void]$adGroupsWithMembers.Add($adGroupWithMembersObject)

            if ($verboseLogging -eq $true) {
                Hid-Write-Status -Event Success "Successfully queried Members of Group [$($adGroup.Name)]. Result count: $(($adGroupMembers | Measure-Object).Count)"
            }
        }
        catch {
            $ex = $PSItem
            $errorMessage = Get-ErrorMessage -ErrorObject $ex
        
            Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"
        
            throw "Error querying Members of Group [$($adGroup.Name)] Error Message: $($errorMessage.AuditErrorMessage)"
        }
    }
    $adGroupsWithMembersGrouped = $adGroupsWithMembers | Group-Object -Property ObjectGUID -AsHashTable -AsString

    Hid-Write-Status -Event Success -Message "Successfully queried AD Groups with members. Result count: $(($adGroupsWithMembers.Users | Measure-Object).Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying AD Groups with members. Error Message: $($errorMessage.AuditErrorMessage)"
}
#endregion Get members of AD Groups

Hid-Write-Status -Event Information -Message "------[Calculations of combined data]------"
# Calculate new and obsolete product assignments
try {
    $newProductAssignmentObjects = [System.Collections.ArrayList]@()
    $obsoleteProductAssignmentObjects = [System.Collections.ArrayList]@()
    $existingProductAssignmentObjects = [System.Collections.ArrayList]@()
    foreach ($product in $helloIDSelfServiceProductsInScopeWithActionsInScope) {
        # if ($verboseLogging -eq $true) {
        #     Hid-Write-Status -Event Information -Message "Calculating new and obsolete product assignments for Product [$($product.name)]"
        # }

        # Get Group from Product Action
        $adGroupGuid = [Guid]::New(($product.code.replace("$ProductSkuPrefix", "")))
        $adGroup = $null
        $adGroup = $adGroupsWithMembersGrouped["$($adGroupGuid)"]
        if (($adGroup | Measure-Object).Count -eq 0) {
            Hid-Write-Status -Event Error -Message "No AD group found with objectGuid [$($adGroupGuid)] for Product [$($product.name)]"
            continue
        }
        elseif (($adGroup | Measure-Object).Count -gt 1) {
            Hid-Write-Status -Event Error -Message "Multiple AD groups found with objectGuid [$($adGroupGuid)] for Product [$($product.name)]. Please correct this so the objectGuid of the AD group is unique"
            continue
        }

        # Get AD user objects for additional data to match to HelloID user
        $adUsersInScope = $adGroup.Users
        
        # Get HelloID user objects to assign to the product
        $productUsersInScope = [System.Collections.ArrayList]@()
        foreach ($adUser in $adUsersInScope) {
            $helloIDUser = $null
            $helloIDUser = $helloIDUsersGrouped["$($adUser.$adUserCorrelationProperty)"]

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
            $currentProductassignments = $helloIDSelfServiceProductassignmentsInScopeGrouped["$($product.productId)"]
        }

        # Define assignments to grant
        $newProductassignments = $productUsersInScope | Where-Object { $_.userGuid -notin $currentProductassignments.userGuid }
        foreach ($newProductAssignment in $newProductassignments) {
            $newProductAssignmentObject = [PSCustomObject]@{
                productGuid            = "$($product.productId)"
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
                productGuid            = "$($product.productId)"
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
                productGuid            = "$($product.productId)"
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
                comment                = "Synchronized assignment from AD Groupmembership"
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
        Hid-Write-Status -Event Success -Message "Successfully synchronized [$(($adGroupsWithMembers.Users | Measure-Object).Count)] Active Directory groupmemberships to [$totalProductAssignments] HelloID Self service Productassignments for [$(($helloIDSelfServiceProductsInScope | Measure-Object).Count)] HelloID Self service Products"
        Hid-Write-Summary -Event Success -Message "Successfully synchronized [$(($adGroupsWithMembers.Users | Measure-Object).Count)] Active Directory groupmemberships to [$totalProductAssignments] HelloID Self service Productassignments for [$(($helloIDSelfServiceProductsInScope | Measure-Object).Count)] HelloID Self service Products"
    }
    else {
        Hid-Write-Status -Event Success -Message "DryRun: Would synchronize [$(($adGroupsWithMembers.Users | Measure-Object).Count)] Active Directory groupmemberships to [$totalProductAssignments] HelloID Self service Productassignments for [$(($helloIDSelfServiceProductsInScope | Measure-Object).Count)] HelloID Self service Products"
        Hid-Write-Summary -Event Success -Message "DryRun: Would synchronize [$(($adGroupsWithMembers.Users | Measure-Object).Count)] Active Directory groupmemberships to [$totalProductAssignments] HelloID Self service Productassignments for [$(($helloIDSelfServiceProductsInScope | Measure-Object).Count)] HelloID Self service Products"
    }
}
catch {
    Hid-Write-Status -Event Error -Message "Error synchronization of [$(($adGroupsWithMembers.Users | Measure-Object).Count)] Active Directory groupmemberships to [$totalProductAssignments] HelloID Self service Productassignments for [$(($helloIDSelfServiceProductsInScope | Measure-Object).Count)] HelloID Self service Products"
    Hid-Write-Status -Event Error -Message "Error at Line [$($_.InvocationInfo.ScriptLineNumber)]: $($_.InvocationInfo.Line)."
    Hid-Write-Status -Event Error -Message "Exception message: $($_.Exception.Message)"
    Hid-Write-Status -Event Error -Message "Exception details: $($_.errordetails)"
    Hid-Write-Summary -Event Failed -Message "Error synchronization of [$(($adGroupsWithMembers.Users | Measure-Object).Count)] Active Directory groupmemberships to [$totalProductAssignments] HelloID Self service Productassignments for [$(($helloIDSelfServiceProductsInScope | Measure-Object).Count)] HelloID Self service Products"
}
#endregion
