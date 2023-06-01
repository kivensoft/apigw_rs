# mapigw -- mini api gateway
简单快速的api网关

---
#### 项目地址
<https://github.com/kivensoft/mapigw>

###### 技术框架
- rust 1.65+ 媲美C语言的强类型开发语言
- tokio 1.26+ 目前最流行也是性能最好的异步io运行时
- hyper 0.14+ http底层协议库，是众多三方web框架使用的基础库
- serde_json 1.0+ 最流行也是速度最快的json序列化库
- anyhow 1.0+ 最流行的错误处理库，增强标准库的错误处理
- log 0.4+ 日志门面库，rust标准库
- chrono 0.4+ 最流行的日期时间处理库
- async-trait 0.1+ 支持异步函数的trait扩展库
- lazy_static 1.4+ 最流行的静态变量初始化扩展库
- asynclog 简单的异步日志库，采用独立线程进行日志输出
- ansicolor 终端支持的ansi颜色扩展库
- appconfig 命令行参数及配置文件参数解析库

---
###### 源代码下载
`git clone git@github.com:kivensoft/mapigw.git`
###### 编译
`cargo build`
###### 运行
`mapigw`
