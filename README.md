
 * Cloudflare Vless：
 * 1. 强烈推荐workers部署GrainTCP.js，如果没有特殊需求，那么只需更改UUID、落地IP，其它默认即可。
 * 2. 完全释放千兆带宽，专为大流量、高负载、巨型吞吐量设计。
 * 3. 无订阅、纯手搓。
 * 4. 客户端path写法,支持域名、txt、Ip，不支持SOCKS5，例如：/?ip=usip.vpndns.net  ;  /?ip=https://raw.githubusercontent.com/hofccyf/myip/refs/heads/main/us.txt  ;  /?ip=66.253.7.79   //建议更改成你自己的落地IP。
 * 5. Txt项目：https://github.com/hofccyf/MyTxt   (  来自：https://github.com/ethgan/Cloudflare_TextSpace_Worker )
 * 6. 支持shadowsocks协议（  来自老王大佬：https://github.com/eooce/Cloudflare-proxy/blob/main/shadowsocks.js  ）  <img width="993" height="924" alt="ss" src="https://github.com/user-attachments/assets/a1002d5f-67b8-4480-8d48-76383222a243" />
 * 7. 支持Ak大佬的turn协议  （  来自：  https://github.com/ToiCF/CF-Workers-TURN  ）
