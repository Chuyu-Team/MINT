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

附作者的回复（也许我是第一个询问许可的人）：
Nevertheless some say that headers cannot be copyrighted and have copied phnt
 verbatim anyway without asking me. So do what you will...