
# # Requires -RunAsAdministrator


#at top of script
if (!
    #current role
    (New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    #is admin?
    )).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
) {
    #elevate script and exit current non-elevated runtime
    Start-Process `
        -FilePath 'powershell' `
        -ArgumentList (
            #flatten to single array
            '-File', $MyInvocation.MyCommand.Source, $args `
            | %{ $_ }
        ) `
        -Verb RunAs
    exit
}

function Export-FirewallRules()
{
	Param($Name = "*", $CSVFile = "", [SWITCH]$JSON, [STRING]$PolicyStore = "ActiveStore", [SWITCH]$Inbound, [SWITCH]$Outbound, [SWITCH]$Enabled, [SWITCH]$Disabled, [SWITCH]$Block, [SWITCH]$Allow)

	#Requires -Version 4.0

	# convert Stringarray to comma separated liste (String)
	function StringArrayToList($StringArray)
	{
		if ($StringArray)
		{
			$Result = ""
			Foreach ($Value In $StringArray)
			{
				if ($Result -ne "") { $Result += "," }
				$Result += $Value
			}
			return $Result
		}
		else
		{
			return ""
		}
	}

	# Filter rules?
	# Filter by direction
	$Direction = "*"
	if ($Inbound -And !$Outbound) { $Direction = "Inbound" }
	if (!$Inbound -And $Outbound) { $Direction = "Outbound" }

	# Filter by state
	$RuleState = "*"
	if ($Enabled -And !$Disabled) { $RuleState = "True" }
	if (!$Enabled -And $Disabled) { $RuleState = "False" }

	# Filter by action
	$Action = "*"
	if ($Allow -And !$Block) { $Action  = "Allow" }
	if (!$Allow -And $Block) { $Action  = "Block" }


	# read firewall rules
	$FirewallRules = Get-NetFirewallRule -DisplayName $Name -PolicyStore $PolicyStore | Where-Object { $_.Direction -like $Direction -and $_.Enabled -like $RuleState -And $_.Action -like $Action }

	# start array of rules
	$FirewallRuleSet = @()

	ForEach ($Rule In $FirewallRules)
	{
        $j =  $FirewallRules.IndexOf($Rule)
        $p = ([Math]::Round($j * 100 / $FirewallRules.Count))        
		Write-Progress -Activity "Processing rule `"$($Rule.DisplayName)`" ($($Rule.Name))" -PercentComplete $p

		# Retrieve addresses,
		$AdressFilter = $Rule | Get-NetFirewallAddressFilter
		# ports,
		$PortFilter = $Rule | Get-NetFirewallPortFilter
		# application,
		$ApplicationFilter = $Rule | Get-NetFirewallApplicationFilter
		# service,
		$ServiceFilter = $Rule | Get-NetFirewallServiceFilter
		# interface,
		$InterfaceFilter = $Rule | Get-NetFirewallInterfaceFilter
		# interfacetype
		$InterfaceTypeFilter = $Rule | Get-NetFirewallInterfaceTypeFilter
		# and security settings
		$SecurityFilter = $Rule | Get-NetFirewallSecurityFilter

		# generate sorted Hashtable
		$HashProps = [PSCustomObject]@{
			Name = $Rule.Name
			DisplayName = $Rule.DisplayName
			Description = $Rule.Description
			Group = $Rule.Group
			Enabled = $Rule.Enabled.ToString()
			Profile = $Rule.Profile.ToString()
			Platform = StringArrayToList $Rule.Platform
			Direction = $Rule.Direction.ToString()
			Action = $Rule.Action.ToString()
			EdgeTraversalPolicy = $Rule.EdgeTraversalPolicy.ToString()
			LooseSourceMapping = $Rule.LooseSourceMapping.ToString()
			LocalOnlyMapping = $Rule.LocalOnlyMapping.ToString()
			Owner = if ($Rule.Owner) { $Rule.Owner.ToString() } else { "" }
			LocalAddress = StringArrayToList $AdressFilter.LocalAddress
			RemoteAddress = StringArrayToList $AdressFilter.RemoteAddress
			Protocol = $PortFilter.Protocol
			LocalPort = StringArrayToList $PortFilter.LocalPort
			RemotePort = StringArrayToList $PortFilter.RemotePort
			IcmpType = StringArrayToList $PortFilter.IcmpType
			DynamicTarget = if ($PortFilter.DynamicTarget) { $PortFilter.DynamicTarget.ToString() } else { "" }
			Program = $ApplicationFilter.Program -Replace "$($ENV:SystemRoot.Replace("\","\\"))\\", "%SystemRoot%\" -Replace "$(${ENV:ProgramFiles(x86)}.Replace("\","\\").Replace("(","\(").Replace(")","\)"))\\", "%ProgramFiles(x86)%\" -Replace "$($ENV:ProgramFiles.Replace("\","\\"))\\", "%ProgramFiles%\"
			Package = if ($ApplicationFilter.Package) { $ApplicationFilter.Package.ToString() } else { "" }
			Service = $ServiceFilter.Service
			InterfaceAlias = StringArrayToList $InterfaceFilter.InterfaceAlias
			InterfaceType = $InterfaceTypeFilter.InterfaceType.ToString()
			LocalUser = $SecurityFilter.LocalUser
			RemoteUser = $SecurityFilter.RemoteUser
			RemoteMachine = $SecurityFilter.RemoteMachine
			Authentication = $SecurityFilter.Authentication.ToString()
			Encryption = $SecurityFilter.Encryption.ToString()
			OverrideBlockRules = $SecurityFilter.OverrideBlockRules.ToString()
		}

		# add to array with rules
		$FirewallRuleSet += $HashProps
	}

	if (!$JSON)
	{ # output rules in CSV format
		if ([STRING]::IsNullOrEmpty($CSVFile)) { $CSVFile = ".\FirewallRules.csv" }
		$FirewallRuleSet | ConvertTo-CSV -NoTypeInformation -Delimiter ";" | Set-Content $CSVFile
	}
	else
	{ # output rules in JSON format
		if ([STRING]::IsNullOrEmpty($CSVFile)) { $CSVFile = ".\FirewallRules.json" }
		$FirewallRuleSet | ConvertTo-JSON | Set-Content $CSVFile
	}
}

Set-Location (Split-Path $MyInvocation.MyCommand.Path)
$OutFolder = "_dump"
$outFile = "dump.zip"
New-Item -ItemType Directory -Force -Path $OutFolder | Out-Null

Write-Host "Get-NetRoute"
Get-NetRoute | Export-Csv -Path "$OutFolder/_route.csv" -NoTypeInformation
Write-Host "Get-Process"
Get-Process | Export-Csv -Path "$OutFolder/_process.csv" -NoTypeInformation
Write-Host "Get-Service"
Get-Service | Export-Csv -Path "$OutFolder/_service.csv" -NoTypeInformation
Write-Host "Get-Service (ext.)"
Get-WmiObject -Class win32_service | Export-Csv -Path "$OutFolder/_serviceExtended.csv" -NoTypeInformation
Write-Host "Get-ComputerInfo"
Get-ComputerInfo | Export-Csv -Path "$OutFolder/_computerinfo.csv" -NoTypeInformation
Write-Host "FirewallRules"
Export-FirewallRules -Inbound -CSVFile "$OutFolder/_firewallExport.csv"


# Create archive
add-type -AssemblyName System.IO.Compression.FileSystem
$zipDestinationFolder = (Get-Item $OutFolder).Parent.FullName
$zipDestinationFile = Join-Path -Path $zipDestinationFolder -ChildPath ("dump.zip")

if (Test-Path $zipDestinationFile) {
    Remove-Item $zipDestinationFile
}

[System.IO.Compression.ZipFile]::CreateFromDirectory($OutFolder, $zipDestinationFile, 'Optimal', $false)
Write-Host !
Write-Host !
Write-Host "Dump is located here: $zipDestinationFile" -ForegroundColor Green


Write-Host -NoNewLine 'Press any key to continue...';
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');

