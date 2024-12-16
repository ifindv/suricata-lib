# suricata-lib

## 简介

本项目在suricata-7.0.2的基础上，进行封装，提供动态库文件以及简明的API接口，方便其它app集成。

## 编译
```
sh build.sh [all | pack]
```

## TODO
1. APP中使用了旧版本的libhtp代码，集成suricata-lib时产生冲突导致segfault，通过重命名旧版本文件名/接口名规避 √
2. 支持多进程模型，为每个进程单独维护一份日志避免冲突，这包含fast.log, eve.json, suricata.log, stats.log √
3. 去除suricata-lib修改主线程的名称 √
4. 去除suricata-lib注册信号处理函数 √
5. 部分日志类型记录时间有误
6. 编译问题（涉及autotools版本不匹配、src/.deps/*.Po文件无法生成、magic编译报错、交叉编译等）
7. 依赖以github子模块的方式引入，目前依赖源码直接放置在deps目录下
8. 支持多线程模型
9. configure去掉--enable-debug选项（release版本）

## API
参见suricata-lib.h

## 说明
- suricata项目原始的README.md保留，重命名为README_.md；

