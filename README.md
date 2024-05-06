# apigw -- mini api gateway
简单快速的api网关，提供基于ipv4的http/1.1反向代理

---
#### 项目地址
<https://github.com/kivensoft/apigw_rs>

###### 技术框架
- rust 1.65+ 媲美C语言的强类型开发语言
- tokio 1.27+ 目前最流行也是性能最好的异步io运行时
- hyper 1.2+ http底层协议库，是众多三方web框架使用的基础库
- serde_json 1.0+ 最流行也是速度最快的json序列化库
- anyhow 1.0+ 最流行的错误处理库，增强标准库的错误处理
- log 0.4+ 日志门面库，rust标准库
- time 0.3+ 官方推荐的日期时间库
- async-trait 0.1+ 支持异步函数的trait扩展库
- compact_str 0.7+ 小字符串内嵌的字符串替代库
- mini-moka 0.10+ 轻量级缓存库，rust版本的Caffeine实现
- dashmap 5.5+ 高性能线程安全map
- smallstr 0.3+ 基于栈的字符串
- rand 0.8+ 最广泛使用的随机数生成库
- asynclog 简单的异步日志库，采用独立线程进行日志输出
- ansicolor 终端支持的ansi颜色扩展库
- appconfig 命令行参数及配置文件参数解析库

---
###### 源代码下载
`git clone git@github.com:kivensoft/apigw_rs.git`
###### 编译
`cargo build`
###### 运行
`apigw`
