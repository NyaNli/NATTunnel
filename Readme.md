# NATTunnel 内网穿透隧道

可以将本地端口转发到一个拥有公网IP的服务器的指定端口上（前提是你得有这么一个服务器）  
支持TCP与UDP，支持SSL传输过程加密（请自备证书文件）  
You can forward the local port to the specified port of a server with public IP.  
Support TCP and UDP, support SSL transmission process encryption (I do not provide the certificate file so you should generate one by yourself).  

原理是将服务器端建立的端口的所有连接、断开、数据事件打包返回本地，在本地进行模拟，再将本地的模拟结果打包发给服务端，由服务端执行响应  
The principle is to package all of the socket events from server and return them to the local place for simulation, and then package the local simulation results to the server for response.  

\[2020-05-30] 重构代码，新增命令行支持，不写代码也可以直接使用功能  

效果图？  
早期开发版：  
![v0.1.12](https://user-images.githubusercontent.com/20377926/83137226-63df7800-a11b-11ea-86a7-e4595f7bc9a8.png)  
代码重构前：  
![v9999.9999.9999](https://user-images.githubusercontent.com/20377926/83137218-60e48780-a11b-11ea-9472-ea1c0f613fe4.png)  
目前版本：  
![SuperUltraFinalVersion](https://user-images.githubusercontent.com/20377926/83316644-92fc0380-a259-11ea-8c02-1f55bcf2bef8.png)