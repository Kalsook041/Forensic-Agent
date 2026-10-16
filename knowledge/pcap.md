# PCAP 题
先用 overview 读取可引用的 derived 汇总：packet_count、protocol_counts、ip_addresses、
ip_address_count、tcp_session_count、tcp_ports、udp_ports，以及捕获时间起止和 duration_seconds。
时间值以精确十进制字符串表示；空匹配的时间值为 null。TCP 会话数按全部匹配输出中的 distinct
tcp.stream 计算，不能按当前展示帧数估计。IP 列表最多展示1000项；若 ip_addresses_complete=false，
不能声称列表已完整。ip_statistics_complete=true 时 ip_address_count 才是完整数量；头部缺失时该值为
null，observed_ip_address_count 仅记录已解码地址数量。

先检查 tcp_statistics_complete。已知 TCP 但缺少可解码 tcp.stream（例如 TCP 头未采集或未重组分片）时，
tcp_session_count=null、tcp_statistics_complete=false、statistics_complete=false；
observed_tcp_session_count 仅为已解码会话数量，不能替代未知总数。网络头缺失也会使完整 IP/TCP 数量未知。
VLAN 使用内层类型识别应有的 IPv4/IPv6 头；内层头未采集时，不能把缺少地址或会话解释为完整的0。
AH 使用其 Next Header 继续检查后继头部：AH 后的 TCP 头缺失时 TCP 总数未知，已完整解码的 IP 地址仍可完整。
AH 自身缺失且后继协议未知时，网络和传输统计均按未知处理，以免遗漏可能的内层 IP。
UDP 头部是否足以统计端口由 udp_statistics_complete 标注。完整性为 false 时，端口列表仅表示已观察值。
frame.cap_len < frame.len 的全部采集截断帧都会导致 partial，并计入 capture_truncated_packet_count。
只有载荷截断而 IP/TCP 头已完整解码时，TCP 会话统计仍可完整；采集缺失的载荷无法恢复，不能推测其内容。

protocol 仅允许 overview、dns、http、tls；ip_address 仅允许一个有效 IPv4/IPv6 地址，
tcp_stream 仅允许非负整数。多个条件取交集，由固定模板构造 TShark 筛选，不接收自由 display filter。
overview 无筛选时 scope.kind=capture；有筛选时 scope.kind=filtered，汇总仅覆盖 scope 中的匹配帧。
statistics_scope=all_matched_packets 表示聚合读取了本次完整工具输出；statistics_complete=true 还要求
网络和传输统计的相关头部均可解码。
不代表当前页展示了全部帧，也不把筛选统计扩展为整个捕获文件的统计。

limit 为1..1000，offset 为0..1000000，按匹配帧顺序从0开始分页。overview 汇总中的
matched_packet_count、returned_packet_count、has_more、next_offset 描述当前页。
需要后页时保留同一 protocol、ip_address、tcp_stream，提交 next_offset；has_more=false 时停止。
dns/http/tls 保留首条帧证据的形状，分页信息位于 warnings 的“PCAP 分页”JSON中。
即使末页 has_more=false，只要省略了前页或后页明细，结果仍为 partial/truncated；这不削弱已完成的汇总。

以 frame.number 定位原始帧，matched_row 是本次筛选结果中的1起始行号。保留捕获文件 SHA256
和原始 TShark 输出；summary 的 aggregation_basis 说明聚合来源，不能从局部帧反推全局数量。
关闭网络名称解析，不根据加密 TLS 载荷猜测账号、密码或正文。工具超时或输出超限时失败，不能当作完整统计。
