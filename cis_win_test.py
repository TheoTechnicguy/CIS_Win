confi_contents = r"""Version:,0.1.3
Note:,Max_val is inclusive --> min=0 max=5 = 0-1-2-3-4-5.,Default source:,xml,Default is_default:,False
Number,Source,Section,Policy_name,Human_readable_policy_name,Type,Min_val,Max_val,Exact_val,is_default
---------------,---------------,---------------,---------------,---------------,---------------,---------------,---------------
1,,,,Account Policies,print,,,Account Policies
1.1,,,,Password Policy,print,,,Passowrd Policies
1.1.1,,rsop:ComputerResults/rsop:ExtensionData/settings:Extension/security:Account,PasswordHistorySize,,!int,24,,
1.1.2,,rsop:ComputerResults/rsop:ExtensionData/settings:Extension/security:Account,MaximumPasswordAge,,int,1,,
1.1.3,,rsop:ComputerResults/rsop:ExtensionData/settings:Extension/security:Account,MinimumPasswordAge,,int,1,,
1.1.4,,rsop:ComputerResults/rsop:ExtensionData/settings:Extension/security:Account,MinimumPasswordLength,,int,14,,
1.1.5,,rsop:ComputerResults/rsop:ExtensionData/settings:Extension/security:Account,PasswordComplexity,,bool,,,!TRUE
1.1.6,,rsop:ComputerResults/rsop:ExtensionData/settings:Extension/security:Account,ClearTextPassword,,bool,,,FALSE
1.2,,,,Account Lockout Policy,print,,,Account Lockout Policies
1.2.1,,rsop:ComputerResults/rsop:ExtensionData/settings:Extension/security:Account,LockoutDuration,,int,15,,
1.2.2,,rsop:ComputerResults/rsop:ExtensionData/settings:Extension/security:Account,LockoutBadCount,,int,1,11,
1.2.3,,rsop:ComputerResults/rsop:ExtensionData/settings:Extension/security:Account,ResetLockoutCount,,int,15,,
2.1,,,,Print This,print,,,
2.2,,,,,print,,,
2.3,,rsop:ComputerResults/rsop:ExtensionData/settings:Extension/security:Account,MaximumPasswordAge,,int,1,,
2.4,,rsop:ComputerResults/rsop:ExtensionData/settings:Extension/security:Account,MaximumPasswordAge,MaxPASS,int,1,,
2.5,xml,rsop:ComputerResults/rsop:ExtensionData/settings:Extension/security:Account,MaximumPasswordAge,FromXML,int,1,,
comment,2.6,registry,Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application,Retention,Registry,int,0,
Comment,Nothing,to,see,here,and ,no,problemo,correct?
2.7,,,,After Comment,print,,,
"""


with open("config.csv") as file:
    assert file.read() == confi_contents, "Config File not correct"

from cis_win import __version__
import datetime

out = (
    r"""Output file version:,"""
    + __version__
    + r""",Execution time:,"""
    + str(datetime.datetime.now())
    + r""",XML execution time:,2020-07-02T06:49:43.0824944Z
User:,Theo2,Domain:,OUMPAH-PAH
Computer:,Oumpah-pah,IP:,192.168.188.100
Note:,Max value inclusive. A Current_val of None might mean 'policy not found in export file'. Integer values of 0 and 1 equal to boolean values False and True.
Validity code:,83789BF910DEBBF03FF0DE934F0137DF259BAA8D72E4B41FB8B0ECE2F4D144F6,Note: THIS FILE IS ONLY VALID IN READ-ONLY MODE AND CORRECT VALIDITY CODE.
DISCLAIMER:,THE CONTENTS OF THIS FILE ONLY REFLECT THE GPO STATE OF THE PC AT EXECUTION TIME.
---------------,---------------,---------------,---------------,---------------,---------------
Number,Source,Section,Policy,Current_val,Min_val,Max_val,Exact_val,Compliant
1,,Account Policies,Account Policies
1.1,,Password Policy,Passowrd Policies
1.1.1,xml,rsop:ComputerResults/rsop:ExtensionData/settings:Extension/security:Account/,PasswordHistorySize,False,24,,,True
1.1.2,xml,rsop:ComputerResults/rsop:ExtensionData/settings:Extension/security:Account/,MaximumPasswordAge,False,1,,,False
1.1.3,xml,rsop:ComputerResults/rsop:ExtensionData/settings:Extension/security:Account/,MinimumPasswordAge,False,1,,,False
1.1.4,xml,rsop:ComputerResults/rsop:ExtensionData/settings:Extension/security:Account/,MinimumPasswordLength,False,14,,,False
1.1.5,xml,rsop:ComputerResults/rsop:ExtensionData/settings:Extension/security:Account/,PasswordComplexity,False,,,!TRUE,False
1.1.6,xml,rsop:ComputerResults/rsop:ExtensionData/settings:Extension/security:Account/,ClearTextPassword,False,,,FALSE,False
1.2,,Account Lockout Policy,Account Lockout Policies
1.2.1,xml,rsop:ComputerResults/rsop:ExtensionData/settings:Extension/security:Account/,LockoutDuration,False,15,,,False
1.2.2,xml,rsop:ComputerResults/rsop:ExtensionData/settings:Extension/security:Account/,LockoutBadCount,False,1,11,,False
1.2.3,xml,rsop:ComputerResults/rsop:ExtensionData/settings:Extension/security:Account/,ResetLockoutCount,False,15,,,False
2.1,,Print This,
2.2,,,
2.3,xml,rsop:ComputerResults/rsop:ExtensionData/settings:Extension/security:Account/,MaximumPasswordAge,False,1,,,False
2.4,xml,rsop:ComputerResults/rsop:ExtensionData/settings:Extension/security:Account/,MaxPASS,False,1,,,False
2.5,xml,rsop:ComputerResults/rsop:ExtensionData/settings:Extension/security:Account/,FromXML,False,1,,,False
2.7,,After Comment,
Compliance integrity:,4DF37DC3F2ACA2676CBA9D24F191F7AF3967B0DC80E647C9397AFCD55119CB08C3B8BB7ED27434261D6C48B1A22F9E93CD85306C000ECDF900CF6BDFC84B3ACC"""
)

with open("out.csv") as file:
    print(__version__, datetime.datetime.now())
    assert file.read() == out
