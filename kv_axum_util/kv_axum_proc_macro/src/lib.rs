
/// 创建可进行json序列化或反序列化的结构体, 可选参数有 ser/deser/opt
///
/// ### Example:
/// ```
/// #[kv_axum_util::bean(ser, opt)]
/// pub struct XUser {
///     pub name: String,
///     age: u32
/// }
/// ```
#[zyn::attribute()]
fn bean(#[zyn(input)] item: zyn::syn::ItemStruct, args: zyn::Args) -> zyn::TokenStream {
    // 判断附加参数是否有 ser 和 deser 和 opt
    let (mut ser, mut deser, mut opt) = (false, false, false);
    for arg in args.iter() {
        if let zyn::Arg::Flag(ident) = arg {
            if ident == "ser" {
                ser = true;
            } else if ident == "deser" {
                deser = true;
            } else if ident == "opt" {
                opt = true;
            }
        }
    }
    // 如果 ser 与 deser 都未设置, 则两者都设置
    if !ser && !deser {
        ser = true;
        deser = true;
    }

    zyn::zyn!(
        // serde的序列化和反序列化属性
        @if (ser) { #[derive(serde::Serialize)] }
        @if (deser) { #[derive(serde::Deserialize)] }

        // struct 自带的属性
        @for (attr in &item.attrs) {
            {{ attr }}
        }

        // 固定添加的属性
        #[serde(rename_all = "camelCase")]

        {{ item.vis }} struct {{ item.ident }} {
            @for (field in &item.fields) {
                @field_declaration(field = field, ser = ser, opt = opt)
            }
        }
    )
}

/// 字段声明
#[zyn::element]
fn field_declaration<'a>(field: &'a zyn::syn::Field, ser: bool, opt: bool) -> zyn::TokenStream {
    zyn::zyn! {
        // 字段自带的属性
        @for (attr in &field.attrs) {
            {{ attr }}
        }

        // 如果是Option类型，则添加序列化忽略值
        @if (*ser && (*opt || is_option_type(&field.ty))) {
            #[serde(skip_serializing_if = "Option::is_none")]
        }

        // 字段声明
        {{ field.vis }} {{ field.ident }}:
        @if (*opt && !is_option_type(&field.ty)) {
            Option<{{ field.ty }}>,
        }
        @else {
            {{ field.ty }},
        }
    }
}

/// 检查类型是否为 Option<T>
fn is_option_type(ty: &zyn::syn::Type) -> bool {
    last_segment_is(ty, "Option")
}

#[allow(dead_code)]
/// 检查类型是否为 Result<T>
fn is_result_type(ty: &zyn::syn::Type) -> bool {
    last_segment_is(ty, "Result")
}

/// 检查类型是否为指定的类型
fn last_segment_is(ty: &zyn::syn::Type, type_name: &str) -> bool {
    if let zyn::syn::Type::Path(type_path) = ty
        && let Some(segment) = type_path.path.segments.last()
    {
        return segment.ident == type_name;
    }
    false
}

#[allow(dead_code)]
/// 检查属性是否为文档注释
fn is_doc_comment(attr: &zyn::syn::Attribute) -> bool {
    use zyn::syn::{Expr, Lit, Meta, MetaNameValue};
    // 首先判断 path 是否是 "doc"
    if !attr.path().is_ident("doc") {
        return false;
    }

    // 解析属性内容
    match &attr.meta {
        // #[doc = "..."] 形式
        Meta::NameValue(MetaNameValue { value, .. }) => {
            if let Expr::Lit(expr_lit) = value {
                if let Lit::Str(_lit_str) = &expr_lit.lit {
                    // _lit_str 就是实际的doc内容
                    return true;
                }
            }
        }
        _ => {}
    }

    false
}


/// get接口定义
///
/// ### Example:
/// ```
/// #[kv_axum_util::api_get("/api/users/{id}")]
/// pub async fn users(Path(id): Path<u32>) -> ApiResult<User> {
///     todo!();
/// }
/// ```
#[zyn::attribute()]
fn api_get(#[zyn(input)] item: zyn::syn::ItemFn, args: zyn::Args) -> zyn::TokenStream {
    zyn::zyn! {
        @route_macro(item = item, args = args, method = 1)
    }
}

/// post接口定义
///
/// ### Example:
/// ```
/// #[kv_axum_util::api_post("/api/user")]
/// pub async fn user() -> ApiResult<()> {
///     todo!();
/// }
/// ```
#[zyn::attribute()]
fn api_post(#[zyn(input)] item: zyn::syn::ItemFn, args: zyn::Args) -> zyn::TokenStream {
    zyn::zyn! {
        @route_macro(item = item, args = args, method = 2)
    }
}

/// api get and post接口定义
///
/// ### Example:
/// ```
/// #[kv_axum_util::api("/api/user/{id}")]
/// pub async fn user(Path(id): Path<u32>) -> ApiResult<User> {
///     todo!();
/// }
/// ```
#[zyn::attribute()]
fn api(#[zyn(input)] item: zyn::syn::ItemFn, args: zyn::Args) -> zyn::TokenStream {
    zyn::zyn! {
        @route_macro(item = item, args = args, method = 0)
    }
}

#[zyn::element]
fn route_macro(item: zyn::syn::ItemFn, args: zyn::Args, method: u32) -> zyn::TokenStream {
    use zyn::{Arg, syn::Lit};
    let path = if let Some(Arg::Lit(Lit::Str(path)))  = args.get_index(0) {
        path.value()
    } else {
        panic!(r#"path required, eg: #[get("/api/v1/users")]"#)
    };

    zyn::zyn!(
        // 原函数
        {{ item }}

        kv_axum_util::inventory::submit! {
            kv_axum_util::RouteEntry {
                path: {{ path }},
                @if (*method == 0) {
                    method_router: axum::routing::{{ "get" | ident:"{}" }}({{ item.sig.ident }}).{{ "post" | ident:"{}" }}({{ item.sig.ident}}),
                }
                @else if (*method == 1) {
                    method_router: axum::routing::{{ "get" | ident:"{}" }}({{ item.sig.ident }}),
                }
                @else {
                    method_router: axum::routing::{{ "post" | ident:"{}" }}({{ item.sig.ident }}),
                }
            }
        }
    )
}
