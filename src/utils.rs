use base64::{Engine, engine::general_purpose};
use serde_json::Value;

/// 规范化路径
pub fn normalize_path(path: &str, end_sep: bool) -> String {
    normalize_paths(std::slice::from_ref(&path), end_sep)
}

/// 拼接多个路径, 形成规范化uri路径
pub fn normalize_paths(paths: &[&str], end_sep: bool) -> String {
    let mut total = 0;
    for path in paths {
        total += path.len() + 1;
    }
    let mut out = Vec::with_capacity(total);

    for path in paths {
        let plen = path.len();
        if plen == 0 { continue; }

        let mut pbs = path.as_bytes();

        if pbs[0] != b'/' {
            out.push(b'/');
        }
        if plen > 1 && pbs[plen - 1] == b'/' {
            pbs = &pbs[0..plen - 1];
        }
        out.extend_from_slice(pbs);
    }

    if out.len() > 1 {
        if out[out.len() - 1] == b'/' {
            if !end_sep {
                out.pop();
            }
        } else if end_sep {
            out.push(b'/');
        }
    }

    unsafe { String::from_utf8_unchecked(out) }
}

/// 解析jwt token中的claims部分, 返回签名和过期时间
pub fn parse_token_sign_exp(token: &str) -> Option<(&str, u64)> {
    fn parse_exp(b64: &str) -> Option<u64> {
        let bytes = general_purpose::URL_SAFE_NO_PAD.decode(b64.as_bytes());
        if let Ok(bytes) = bytes
            && let Ok(claims) = serde_json::from_slice::<Value>(&bytes)
            && let Some(exp) = claims.get("exp")
            && let Some(exp) = exp.as_u64()
        {
            return Some(exp);
        }
        None
    }

    let mut iter = token.split('.');
    // 跳过头部
    if iter.next().is_some() {
        // 读取claims部分 && 读取签名部分
        if let Some(claims_b64) = iter.next()
            && let Some(exp) = parse_exp(claims_b64)
            && let Some(sign) = iter.next()
        {
            return Some((sign, exp));
        }
    }
    None
}

/// 从 vec 中删除 indices 指定索引值的元素, indices 的索引值必须从小到大排列,
/// 注意, 删除的方式是从后到前, 将数组最后1个元素移动到被删除位置, 从而避免整个移动数组,
/// 但这样的缺点是删除后排序与原来的并不一致
#[allow(dead_code)]
pub fn remove_from_vec<T>(vec: &mut Vec<T>, indices: &[u32]) {
    for &idx in indices.iter().rev() {
        let idx = idx as usize;
        if let Some(last) = vec.pop() {
            let last_idx = vec.len();
            if idx != last_idx {
                let _ = std::mem::replace(&mut vec[idx], last);
            }
        }
    }
}

/// 返回字符串 input 不大于最大长度的长度
#[allow(dead_code)]
pub fn str_max_size(input: &str, max: usize) -> usize {
    if input.len() <= max {
        input.len()
    } else {
        // 找到第256个字节之前的最后一个字符边界
        let mut end = max;
        while !input.is_char_boundary(end) {
            end -= 1;
        }
        end
    }
}
