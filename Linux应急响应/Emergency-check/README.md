<!--
 * @Author: chriskali
 -->
# Emergency Alert Script

> Author: [chriskali](https://github.com/chriskaliX)

> 这是一款linux下的简单应急响应脚本。这是我在学习GScan之后的学习成果，GScan是一个不论在学习和应急响应上都很好的工具。

> This Script is use for check linux emergency security check.This script is my production of learning [Gscan](https://github.com/grayddq/GScan). GScan is a great tool to both learn and do emergency check.

## Author

ChriskaliX

## Usage

python3 main.py

(ONLY python>3.6 supported)

## Run pic

![image](https://github.com/CnHack3r/Awesome-hacking-tools/blob/main/Linux%E5%BA%94%E6%80%A5%E5%93%8D%E5%BA%94/Emergency-check/imgs/showpic.png)

## Check list

> Backdoor

|Checklist|
|-|
|LD_PRELOAD|
|LD_AOUT_PRELOAD|
|LD_ELF_PRELOAD|
|LD_LIBRARY_PATH|
|PROMPT_COMMAND|
|Ld_so_preload|
|Cron_check|
|SSH Process|
|SSH Softlink|
|SSH wrapper|
|Inted|
|Xinetd|
|Setuid|
|Chmod 777(Useless maybe?)|
|Startup check|
|Alias|

> Configuration

|Checklist|
|-|
|Dns check|
|Iptables check|
|Host check|
|Promiscuous check|

> History Check

|Checklist|
|-|
|History check|

> Log Check

|Checklist|
|-|
|wtmp|
|utmp|
|lastlog|
|authlog|

> Process Check

|Checklist|
|-|
|cpu_mem_check|
|shell_check|
|exe_check|

> User Check

|Checklist|
|-|
|root check|
|empty check|
|sudo check|
|authorized_check|
|permission_check|

## Difference

- Pure python3,No Linux command used
- some differences between file check
- delete some plugins

## Update log

- 2019-11-01:
  - fix the softlink problem
  - fix the logical of backdoor check
- 2020-03-16:
  - some explations
  - add ruby detect in analysis file

## Others & Reference

- https://xz.aliyun.com/t/7338
