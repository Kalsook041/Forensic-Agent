# PCAP 题
先查看 overview 的帧数和协议统计，再用 dns、http 或 tls 缩小方向。
以 frame.number 定位，保留捕获文件 SHA256 和原始 TShark 输出。
关闭网络名称解析，不根据加密 TLS 载荷猜测账号、密码或正文。
