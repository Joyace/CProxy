CProxy     http://cmwap.wang/  
======  
  
C语言写的一个TCP、DNS代理客户端 
以HTTP请求报文的形式发送到目标服务器  
可以修改HTTP请求头    

### 编译:  
~~~~~
Linux/Android:  
    make [DEFS=-DINLINE]  
Android-ndk:  
    ndk-build  
~~~~~

启动：  
./CProxy CPrpxy.conf  
关闭：  
./CProxy stop  
查询运行状态：  
./CProxy status  

