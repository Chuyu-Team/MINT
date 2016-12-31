NativeLib

该库涵盖了了几乎全部的用户模式可用的NT本机API和Windows窗口站API的声明与定义

该库基于Process Hacker的PHNT库，我对该库进行了大幅度修改
（去除了内核模式定义和整合了头文件，而且对里面的宏进行了标准化处理）

为了对Process Hacker的作者Wen Jia Liu表示感谢
我把我的整理成果单独发在github
不会有任何协议限制
如果你想感激的话，就请感谢Process Hacker作者的大度吧

协议：无（致敬Process Hacker作者）
用法：直接Include此头文件即可(前提你要在这之前Include Windows.h)
建议的Windows SDK版本：10.0.10586及以后

附：Process Hacker的PHNT库的相关内容
项目首页：http://processhacker.sourceforge.net/
介绍和授权：
PHNT这是一个非常全的Native API定义库；我通过邮件获取了作者许可

附：作者的回复（也许我是第一个询问许可的人）：
Nevertheless some say that headers cannot be copyrighted and have copied phnt
 verbatim anyway without asking me. So do what you will...

M2.Native或NativeAPI 2.0
1.修复一些定义的错误
2.增加对Zw开头系统调用的定义
3.增加NTSTATUS的定义
4.扩充基本的NT结构定义
5.增添我和原作者的邮件内容（为什么不做任何的开源协议限制的原因）
6.内置解决WINNT_WIN10_TH2和_WIN32_WINNT_WIN10_RS1未定义导致编译失败的问题
7.内置包含Windows IO操作定义

M2.WinSta或WinStationLib 1.1
完善内容以便引用

M2.Native或NativeAPI 1.0
初始版本

M2.WinSta或WinStationLib 1.0
初始版本
