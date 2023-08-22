//! Unix Crypt(3) 加密算法实现
use std::cmp::min;

use anyhow::Result;
use md5::{Md5, Digest};
use rand::Rng;

const SALT_LEN: usize = 8;
const DIGEST_LEN: usize = 22;
const SALT_MAGIC: &str = "$1$";
const DIGEST_OFFSET: usize = SALT_MAGIC.len() + SALT_LEN + 1;
const PWD_LEN: usize = DIGEST_OFFSET + DIGEST_LEN;

const CRYPT_B64_CHARS: &[u8] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// 口令加密
pub fn encrypt(password: &str) -> Result<String> {
    let mut salt_base64 = [0; SALT_LEN];

    gensalt(&mut salt_base64);

    let mut pass_out = [0; PWD_LEN];
    do_encrypt(&mut pass_out, password.as_bytes(), &salt_base64);

    Ok(String::from(std::str::from_utf8(&pass_out)?))
}

/// 口令校验
pub fn verify(pw_plain: &str, pw_encrypt: &str) -> Result<bool> {
    if pw_encrypt.len() < PWD_LEN || !pw_encrypt.starts_with(SALT_MAGIC) {
        anyhow::bail!("密码格式错误")
    }

    let digest = pw_encrypt.as_bytes();
    let salt_base64 = &digest[SALT_MAGIC.len()..DIGEST_OFFSET - 1];

    let mut pass_out = [0; PWD_LEN];
    do_encrypt(&mut pass_out, pw_plain.as_bytes(), salt_base64);

    let verify_result = pass_out == digest;
    if !verify_result {
        log::trace!("密码校验错误: 原密码 = [{}], 计算结果 = [{}], 期望结果 = [{}]",
                pw_plain, std::str::from_utf8(&pass_out).unwrap(), pw_encrypt);
    }

    Ok(verify_result)
}

fn gensalt(out: &mut [u8]) {
    debug_assert!(out.len() == SALT_LEN);
    let mut rng = rand::thread_rng();
    for item in out.iter_mut().take(SALT_LEN) {
        *item = CRYPT_B64_CHARS[rng.gen_range(0..CRYPT_B64_CHARS.len())];
    }
}

fn do_encrypt(out: &mut [u8], password: &[u8], salt: &[u8]) {
    // 加密方式 Uinx Md5Crypt
    debug_assert!(out.len() >= PWD_LEN && salt.len() == SALT_LEN);

    // 计算 password + salt_prefix + salt 的 md5
    let mut hasher = Md5::new();
    hasher.update(password);
    hasher.update(SALT_MAGIC.as_bytes());
    hasher.update(salt);

    // 计算 password + salt + password 的 md5
    let mut hasher1 = Md5::new();
    hasher1.update(password);
    hasher1.update(salt);
    hasher1.update(password);
    let mut final_state = hasher1.finalize();

    let mut pwd_len = password.len();
    while pwd_len > 0 {
        hasher.update(&final_state[..min(pwd_len, 16)]);
        pwd_len = pwd_len.saturating_sub(16)
    }

    final_state.fill(0);

    pwd_len = password.len();
    let (fs2, p2) = (&final_state[..1], &password[..1]);
    while pwd_len > 0 {
        if (pwd_len & 1) == 1 {
            hasher.update(fs2);
        } else {
            hasher.update(p2);
        }
        pwd_len >>= 1;
    }

    let mut final_state = hasher.finalize();

    // 循环1000次进行hash，别问我为什么这样实现，标准unix crypt(3)算法就是这么实现的
    for i in 0..1000 {
        let mut hasher2 = Md5::new();

        if (i & 1) != 0 {
            hasher2.update(password);
        } else {
            hasher2.update(&final_state[..16]);
        }

        if (i % 3) != 0 {
            hasher2.update(salt);
        }

        if (i % 7) != 0 {
            hasher2.update(password);
        }

        if (i & 1) != 0 {
            hasher2.update(&final_state[..16]);
        } else {
            hasher2.update(password);
        }

        final_state = hasher2.finalize();
    }

    // 将 "$1$" 写入返回参数
    let fs = &mut out[..SALT_MAGIC.len()];
    fs.copy_from_slice(SALT_MAGIC.as_bytes());

    // 将 salt 内容写入返回参数
    let fs = &mut out[SALT_MAGIC.len()..DIGEST_OFFSET - 1];
    fs.copy_from_slice(salt);

    // 将 "$" 写入返回参数
    out[DIGEST_OFFSET - 1] = b'$';

    // 将 password 加密后的结果进行base64编码，并写入返回参数
    let fs = &mut out[DIGEST_OFFSET..];
    u8_to_b64(&mut fs[0..4],   final_state[0], final_state[6],  final_state[12]);
    u8_to_b64(&mut fs[4..8],   final_state[1], final_state[7],  final_state[13]);
    u8_to_b64(&mut fs[8..12],  final_state[2], final_state[8],  final_state[14]);
    u8_to_b64(&mut fs[12..16], final_state[3], final_state[9],  final_state[15]);
    u8_to_b64(&mut fs[16..20], final_state[4], final_state[10], final_state[5]);
    u8_to_b64(&mut fs[20..22], 0,              0,               final_state[11]);

}

fn u8_to_b64(out: &mut [u8], b1: u8, b2: u8, b3: u8) {
    let mut w = (((b1 as u32) << 16) & 0x00FFFFFF)
            | (((b2 as u32) << 8) & 0x00FFFF)
            | ((b3 as u32) & 0xff);

    for item in out {
        *item = CRYPT_B64_CHARS[(w as usize) & 0x3F];
        w >>= 6;
    }
}
