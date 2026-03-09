/// Iterate over JNI parameter type boundaries in a signature string.
/// Calls `visitor(start, end)` for each parameter's byte range within the '(' ... ')'.
fn for_each_jni_param(sig: &str, mut visitor: impl FnMut(usize, usize)) {
    let bytes = sig.as_bytes();
    let mut i = 0;
    while i < bytes.len() && bytes[i] != b'(' {
        i += 1;
    }
    i += 1; // skip '('
    while i < bytes.len() && bytes[i] != b')' {
        let start = i;
        match bytes[i] {
            b'L' => {
                while i < bytes.len() && bytes[i] != b';' {
                    i += 1;
                }
                i += 1; // skip ';'
            }
            b'[' => {
                while i < bytes.len() && bytes[i] == b'[' {
                    i += 1;
                }
                if i < bytes.len() && bytes[i] == b'L' {
                    while i < bytes.len() && bytes[i] != b';' {
                        i += 1;
                    }
                    i += 1;
                } else {
                    i += 1; // primitive element
                }
            }
            _ => i += 1, // primitive
        }
        visitor(start, i);
    }
}

/// Count the number of parameters in a JNI method signature.
/// "(II)V" → 2, "(Ljava/lang/String;I)V" → 2, "()V" → 0
pub(super) fn count_jni_params(sig: &str) -> usize {
    let mut count = 0;
    for_each_jni_param(sig, |_, _| count += 1);
    count
}

/// Parse a JNI method signature into individual parameter type descriptors.
/// "(ILjava/lang/String;[B)V" → ["I", "Ljava/lang/String;", "[B"]
pub(super) fn parse_jni_param_types(sig: &str) -> Vec<String> {
    let bytes = sig.as_bytes();
    let mut result = Vec::new();
    for_each_jni_param(sig, |start, end| {
        result.push(String::from_utf8_lossy(&bytes[start..end]).to_string());
    });
    result
}
