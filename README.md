支持五协议：Vless+Trojan+Xhttp+Turn+Shadowsocks

没有特别需要，仅需更改UUID即可部署

使用xhttp协议需要开启域名的gRPC，节点域名需使用开启了gRPC的自定义域名

支持workers、pages、snippets部署，CF免费计划用户推荐workers部署，并使用Xhttp协议

支持跟随优选地址自动匹配落地地址，无需单独配置proxyip，CF官方反代地址可以秒过CF盾

客户端path必须必须必须为：/id=你的UUID，如果需要自定义proxyip，按以下格式填写，支持TXT解码,格式：/id=你的UUID/ip=1.1.1.1  ；  /id=你的UUID/ip=1.com  ;  /id=你的UUID/ip=1.com/ip.txt  ；
如果使用优选订阅器也可颠倒顺序，例如：/ip=1.1.1.1/id=你的UUID

各协议配置图如下：

<img width="1726" height="708" alt="gRPC" src="https://github.com/user-attachments/assets/c437ceaf-c81f-46d0-9cf0-5468236adbd7" />

<img width="987" height="857" alt="Shadowsocks" src="https://github.com/user-attachments/assets/d4515f51-0850-4e58-93c6-3ac5ec9e1a5c" />

<img width="987" height="861" alt="Trojan" src="https://github.com/user-attachments/assets/18bb95f1-3933-4ded-9c69-6b71dd40cabc" />

<img width="985" height="863" alt="Turn" src="https://github.com/user-attachments/assets/aea22fe2-0729-4f94-82a6-629cc57d6116" />

<img width="991" height="859" alt="Vless" src="https://github.com/user-attachments/assets/d5046585-ddfe-4976-9803-28529c987e19" />

<img width="990" height="858" alt="Xhttp" src="https://github.com/user-attachments/assets/bd777994-50a3-4887-8849-ea1e51c59247" />

