use compact_str::CompactString;


pub fn concat_uri_path(paths: &[&str], end_sep: bool) -> CompactString {
    let mut out = CompactString::with_capacity(0);

    for path in paths {
        let plen = path.len();
        let pbs = path.as_bytes();
        if plen > 0 && (plen > 1 || pbs[0] != b'/') {
            if pbs[0] != b'/' {
                out.push('/');
            }

            let path = if pbs[plen - 1] != b'/' {
                *path
            } else {
                &path[..plen-1]
            };
            out.push_str(path);
        }
    }

    if end_sep {
        out.push('/');
    }

    out
}
