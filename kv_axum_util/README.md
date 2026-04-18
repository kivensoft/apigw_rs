# ansicolor -- terminal ansi color libraty
tracing日志库的定制化库

---
#### 项目地址
<https://github.com/kivensoft/tracing_ext>

###### 技术框架

---
###### 添加依赖
`cargo add --git https://github.com/kivensoft/tracing_ext tracing_ext`
###### 使用
```rust
use tracing_ext;

fn main() {
	// 初始化日志
    let _guard = tracing_ext::TracingBuilder::new()
        .directives(&ac.log_filter)
        .file("logs", "app")
        .disable_console(ac.no_console)
        .build();

	tracing::info!("hello world");
}
```
