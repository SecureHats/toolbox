<#
    .SYNOPSIS
        This command creates Sentinel Alert Rules from all available alert rule templates for which data connectors are configured.
    .DESCRIPTION
        This command creates Sentinel Alert Rules from all available alert rule templates for which data connectors are configured.
    .PARAMETER WorkSpaceName
        Enter the Log Analytics workspace name (required)
    .PARAMETER ResourceGroupName
        Enter the Resource Group name of Log Analytics workspace (required)
    .NOTES
        AUTHOR: Tobias Kritten
        LASTEDIT: 14 Feb 2021
    .EXAMPLE
        Create-AzSentinelAnalyticsRulesFromTemplates -WorkspaceName "workspacename" -ResourceGroupName "rgname"
        The script will create Azure Sentinel Alert Rules in Workspace "workspacename"      
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$FilesPath,

    [Parameter(Mandatory = $true)]
    [string]$OutputPath
    
)

#Region Install Modules
$modulesToInstall = @(
    'powershell-yaml'
)

$modulesToInstall | ForEach-Object {
    if (-not (Get-Module -ListAvailable -All $_)) {
        Write-Output "Module [$_] not found, INSTALLING..."
        Install-Module $_ -Force
        Import-Module $_ -Force
    }
}
#EndRegion Install Modules

#Region HelperFunctions
function Convert-TriggerOperator {
    param (
        [Parameter(Mandatory = $true)]
        [string]$value
    )

    switch ($value) {
        "gt" { $value = "GreaterThan" }
        "lt" { $value = "LessThan" }
        "eq" { $value = "Equal" }
        "ne" { $value = "NotEqual" }
        default { $value }
    }
    return $value
}

function ConvertTo-ISO8601 {
    param (
        [Parameter(Mandatory = $true)]
        [string]$value
    )

    switch -regEx ($value.ToUpper()) {
        '[hmHM]$' {
            return ('PT{0}' -f $value).ToUpper()
        }
        '[dD]$' {
            return ('P{0}' -f $value).ToUpper()
        }
        default {
            return $value.ToUpper()
        }
    }
}

function ConvertTo-ARM {
    param (
        [Parameter(Mandatory = $true)]
        [object]$value,

        [Parameter(Mandatory = $true)]
        [string]$outputFile
    )

    $template = [pscustomobject]@{
        '$schema'      = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
        contentVersion = "1.0.0.0"
        parameters     = @{
            workspace     = @{
                type = "string"
            }
            alertRuleName = [pscustomobject]@{
                type         = "string"
                defaultValue = "$($value.properties.displayName)"
            }
        }
        resources      = @(
            [pscustomobject]@{
                id         = "[format('{0}/alertRules/{1}', resourceId('Microsoft.OperationalInsights/workspaces/providers', parameters('workspace'), 'Microsoft.SecurityInsights'), guid(string(parameters('alertRuleName'))))]"
                name       = "[format('{0}/{1}/{2}', parameters('workspace'), 'Microsoft.SecurityInsights', guid(string(parameters('alertRuleName'))))]"
                type       = "Microsoft.OperationalInsights/workspaces/providers/alertRules"
                kind       = "Scheduled"
                apiVersion = "2021-03-01-preview"
                properties = $body.properties
            }
        )
    }
    
    $template | ConvertTo-Json -Depth 20 | Out-File $outputFile -ErrorAction Stop
}
#EndRegion HelperFunctions

#Region Fetching AlertRules
foreach ($rule in $analyticsRules) {

    try {
        $analyticsRules = Get-ChildItem -Path $FilesPath -Include "*.yaml", "*.yml" -Recurse -ErrorAction 'Stop'
    }
    catch {
        Write-Error $_.Exception.Message
        break
    }
}
#EndRegion Fetching AlertRules

#Region Processing AlertRules
if ($null -ne $analyticsRules) {
    foreach ($rule in $analyticsRules) {
        try {
            $ruleObject = get-content $rule | ConvertFrom-Yaml

            switch ($ruleObject.kind) {
                "MicrosoftSecurityIncidentCreation" {  
                    $body = @{
                        "kind"       = "MicrosoftSecurityIncidentCreation"
                        "properties" = @{
                            "enabled"       = "true"
                            "productFilter" = $ruleObject.productFilter
                            "displayName"   = $ruleObject.displayName
                        }
                    }
                }
                "Scheduled" {
                    $body = [pscustomobject]@{
                        "kind"       = "Scheduled"
                        "properties" = @{
                            "displayName"              = $ruleObject.name
                            "description"              = $ruleObject.description
                            "severity"                 = $ruleObject.severity
                            "enabled"                  = $true
                            "query"                    = $ruleObject.query
                            "queryFrequency"           = ConvertTo-ISO8601 $ruleObject.queryFrequency
                            "queryPeriod"              = ConvertTo-ISO8601 $ruleObject.queryPeriod
                            "triggerOperator"          = Convert-TriggerOperator $ruleObject.triggerOperator
                            "triggerThreshold"         = $ruleObject.triggerThreshold
                            "suppressionDuration"      = "PT5H"  #Azure Sentinel requires a value here, although suppression is disabled
                            "suppressionEnabled"       = $false
                            "tactics"                  = $ruleObject.tactics
                            "techniques"               = $ruleObject.relevantTechniques
                            "alertRuleTemplateName"    = $ruleObject.id
                            "entityMappings"           = $ruleObject.entityMappings
                            "incidentConfiguration"    = $ruleObject.incidentConfiguration
                            "sentinelEntitiesMappings" = $ruleObject.sentinelEntitiesMappings
                            "eventGroupingSettings"    = $ruleObject.eventGroupingSettings
                            "templateVersion"          = $ruleObject.version
                        }
                    }
                    
                    # Update duration to ISO8601
                    if ($null -ne $ruleObject.incidentConfiguration) {
                        $body.properties.incidentConfiguration.groupingConfiguration.lookbackDuration = ConvertTo-ISO8601 $ruleObject.incidentConfiguration.groupingConfiguration.lookbackDuration
                    }
                }
                Default { }
            }
        }
        catch {
            Write-Error $_.Exception.Message
            break
        }
        ConvertTo-ARM -value $body -outputFile ('{0}/{1}.json' -f ($($rule.DirectoryName), $($rule.BaseName)))
    }
}
#EndRegion Processing AlertRules
