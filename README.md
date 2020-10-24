# daily_script

## auto_judge_bits.py

该脚本的作用是判断一个动态链接库文件（Windows的DLL和Linux中的so都可以）是32位程序还是64位程序。

脚本的用法：`python auto_judge_bits.py 动态链接库的地址`
返回结果：例如`('Windows',64)`

说明：这个代码在判断DLL文件的位数时，借鉴了网上的一个方法，但是由于不知道原帖是谁的，所以没有把原链接贴出来