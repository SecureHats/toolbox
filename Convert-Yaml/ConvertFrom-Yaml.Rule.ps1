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

## Make sure any modules we depend on are installed
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

# Fetching Alert Rule templates

foreach ($rule in $analyticsRules) {
    
    try {
        $analyticsRules = Get-ChildItem -Path $FilesPath -Include "*.yaml", "*.yml" -Recurse -ErrorAction 'Stop'
    } catch {
        Write-Error $_.Exception.Message
        break
    }
}

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

# Processing Alert Rule templates

if ($null -ne $analyticsRules) {
    Write-Verbose "found $($analyticsRules.count) to process"
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
				$body = @{
					"kind"       = "Scheduled"
					"properties" = @{
						"enabled"               = "true"
						"alertRuleTemplateName" = $ruleObject.id
						"displayName"           = $ruleObject.displayName
						"description"           = $ruleObject.description
						"severity"              = $ruleObject.severity
						"tactics"               = $ruleObject.tactics
                        "techniques"            = $ruleObject.relevantTechniques
						"query"                 = $ruleObject.query
						"queryFrequency"        = ConvertTo-ISO8601 $ruleObject.queryFrequency
						"queryPeriod"           = ConvertTo-ISO8601 $ruleObject.queryPeriod
						"triggerOperator"       = Convert-TriggerOperator $ruleObject.triggerOperator
						"triggerThreshold"      = $ruleObject.triggerThreshold
						"suppressionDuration"   = "PT5H"  #Azure Sentinel requires a value here, although suppression is disabled
						"suppressionEnabled"    = $false
					}
				}
			}
			Default { }
            }
        } catch {
            Write-Error $_.Exception.Message
            break
        }
    }
}


    <#
        If OutPut folder defined then test if exists otherwise create folder
    #>

    <#

    <#
        If any YAML file found starte lopp to process all the files
    #>
    if ($content) {
        Write-Verbose "'$($content.count)' templates found to convert"

        # Start Loop
        $content | ForEach-Object {
            <#
                Define JSON template format
            #>
            $template = [PSCustomObject]@{
                '$schema'      = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
                contentVersion = "1.0.0.0"
                Parameters     = @{
                    Workspace = @{
                        type = "string"
                    }
                }
                resources      = @(
                    [PSCustomObject]@{
                        id         = ""
                        name       = ""
                        type       = "Microsoft.OperationalInsights/workspaces/providers/alertRules"
                        kind       = "Scheduled"
                        apiVersion = "2021-03-01-preview"
                        properties = [PSCustomObject]@{}
                    }
                )
            }

            # Update the template format with the data from YAML file
            $convert = $_ | Get-Content -Raw | ConvertFrom-Yaml -ErrorAction Stop | Select-Object * -ExcludeProperty relevantTechniques, kind, requiredDataConnectors, version, tags
            $($template.resources).id = "[concat(resourceId('Microsoft.OperationalInsights/workspaces/providers', parameters('workspace'), 'Microsoft.SecurityInsights'),'/alertRules/" + $convert.id + "')]"
            $($template.resources).name = "[concat(parameters('workspace'),'/Microsoft.SecurityInsights/" + $convert.id + "')]"
            $($template.resources).properties = ($convert | Select-Object * -ExcludeProperty id)

            #Based of output path variable export files to the right folder
            if ($null -ne $expPath) {
                $outputFile = $expPath + "/" + $($_.BaseName) + ".json"
            }
            else {

                $outputFile = $($_.DirectoryName) + "/" + $($_.BaseName) + ".json"
            }

            #Export to JSON
            try {
                $template | ConvertTo-Json -Depth 20 | Out-File $outputFile -ErrorAction Stop
            }
            catch {
                Write-Error $_.Exception.Message
            }
        }
    }
    else {
        Write-Warning "No YAML templates found"
    }
}