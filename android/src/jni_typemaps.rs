mod swig_foreign_types_map {}

foreign_typemap!(
    ($p:r_type) <T> Result<T> => swig_i_type!(T) {
        $out = match $p {
            Ok(x) => {
                swig_from_rust_to_i_type!(T, x, ret)
                ret
            }
            Err(err) => {
                let msg = err.to_string();
                let exception_class = match err {
                    Error::UrlParse(_) => swig_jni_find_class!(ETEBASE_UrlParseException, "com/etebase/client/exceptions/UrlParseException"),
                    Error::MsgPackEncode(_) => swig_jni_find_class!(ETEBASE_MsgPackEncodeException, "com/etebase/client/exceptions/MsgPackEncodeException"),
                    Error::MsgPackDecode(_) => swig_jni_find_class!(ETEBASE_MsgPackDecodeException, "com/etebase/client/exceptions/MsgPackDecodeException"),
                    Error::ProgrammingError(_) => swig_jni_find_class!(ETEBASE_ProgrammingErrorException, "com/etebase/client/exceptions/ProgrammingErrorException"),
                    Error::Padding(_) => swig_jni_find_class!(ETEBASE_PaddingException, "com/etebase/client/exceptions/PaddingException"),
                    Error::Base64(_) => swig_jni_find_class!(ETEBASE_Base64Exception, "com/etebase/client/exceptions/Base64Exception"),
                    Error::Integrity(_) => swig_jni_find_class!(ETEBASE_IntegrityException, "com/etebase/client/exceptions/IntegrityException"),
                    Error::Encryption(_) => swig_jni_find_class!(ETEBASE_EncryptionException, "com/etebase/client/exceptions/EncryptionException"),
                    Error::Unauthorized(_) => swig_jni_find_class!(ETEBASE_UnauthorizedException, "com/etebase/client/exceptions/UnauthorizedException"),
                    Error::Conflict(_) => swig_jni_find_class!(ETEBASE_ConflictException, "com/etebase/client/exceptions/ConflictException"),
                    Error::PermissionDenied(_) => swig_jni_find_class!(ETEBASE_PermissionDeniedException, "com/etebase/client/exceptions/PermissionDeniedException"),
                    Error::Connection(_) => swig_jni_find_class!(ETEBASE_ConnectionException, "com/etebase/client/exceptions/ConnectionException"),
                    Error::Http(_) => swig_jni_find_class!(ETEBASE_HttpException, "com/etebase/client/exceptions/HttpException"),
                    _ => swig_jni_find_class!(ETEBASE_EtebaseException, "com/etebase/client/exceptions/EtebaseException"),
                };
                jni_throw(env, exception_class, &msg);
                return <swig_i_type!(T)>::jni_invalid_value();
            }
        };
    };
    ($p:f_type, unique_prefix="/*etebase::error::Result<swig_subst_type!(T)>*/") => "/*etebase::error::Result<swig_subst_type!(T)>*/swig_f_type!(T)"
        "swig_foreign_from_i_type!(T, $p)";
);

foreign_typemap!(
    ($p:r_type) Option<&str> => internal_aliases::JStringOptStr {
        $out = match $p {
            Some(s) => from_std_string_jstring(s.to_owned(), env),
            None => ::std::ptr::null_mut(),
        };
    };
    ($p:f_type, option = "NoNullAnnotations") => "java.util.Optional<String>" r#"
        $out = java.util.Optional.ofNullable($p);
"#;
    ($p:f_type, option = "NullAnnotations") => "@NonNull java.util.Optional<String>" r#"
        $out = java.util.Optional.ofNullable($p);
"#;
);

foreign_typemap!(
    ($p:r_type) Vec<u8> => jbyteArray {
        let slice = &($p)[..];
        let slice = unsafe { std::mem::transmute::<&[u8], &[i8]>(slice) };
        let raw = JavaByteArray::from_slice_to_raw(slice, env);
        $out = raw;
    };
    ($p:f_type) => "jbyteArray";
);

foreign_typemap!(
    ($p:r_type) &'a [u8] => jbyteArray {
        let slice = unsafe { std::mem::transmute::<&[u8], &[i8]>($p) };
        let raw = JavaByteArray::from_slice_to_raw(slice, env);
        $out = raw;
    };
    ($p:f_type) => "jbyteArray";
    ($p:r_type) &'a [u8] <= jbyteArray {
        let arr = JavaByteArray::new(env, $p);
        let slice = arr.to_slice();
        let slice = unsafe { std::mem::transmute::<&[i8], &[u8]>(slice) };
        $out = slice;
    };
    ($p:f_type) <= "jbyteArray";
);

foreign_typemap!(
    ($p:r_type) Option<&'a [u8]> <= jbyteArray {
        $out = if !$p.is_null() {
            let arr = JavaByteArray::new(env, $p);
            let slice = arr.to_slice();
            let slice = unsafe { std::mem::transmute::<&[i8], &[u8]>(slice) };
            Some(slice)
        } else {
            None
        };
    };
    ($p:f_type) <= "jbyteArray";
);

#[allow(dead_code)]
fn jobject_array_to_vec_of_refs<T: SwigForeignClass>(
    env: *mut JNIEnv,
    arr: internal_aliases::JForeignObjectsArray<T>,
) -> Vec<&'static T> {
    let field_id = <T>::jni_class_pointer_field();
    assert!(!field_id.is_null());
    let length = unsafe { (**env).GetArrayLength.unwrap()(env, arr.inner) };
    let len = <usize as ::std::convert::TryFrom<jsize>>::try_from(length)
        .expect("invalid jsize, in jsize => usize conversation");
    let mut result = Vec::with_capacity(len);
    for i in 0..length {
        let native: &mut T = unsafe {
            let obj = (**env).GetObjectArrayElement.unwrap()(env, arr.inner, i);
            if (**env).ExceptionCheck.unwrap()(env) != 0 {
                panic!("Failed to retrieve element {} from this `jobjectArray'", i);
            }
            let ptr = (**env).GetLongField.unwrap()(env, obj, field_id);
            let native = (jlong_to_pointer(ptr) as *mut T).as_mut().unwrap();
            (**env).DeleteLocalRef.unwrap()(env, obj);
            native
        };
        result.push(&*native);
    }

    result
}

foreign_typemap!(
    ($p:r_type) <'a, T: SwigForeignClass> Vec<&'a T> <= internal_aliases::JForeignObjectsArray<T> {
        $out = jobject_array_to_vec_of_refs(env, $p);
    };
    ($p:f_type, option = "NoNullAnnotations") <= "swig_f_type!(T) []";
    ($p:f_type, option = "NullAnnotations") <= "@NonNull swig_f_type!(T, NoNullAnnotations) []";
);

foreign_typemap!(
    ($p:r_type) <T: SwigForeignClass> &Vec<T> => internal_aliases::JForeignObjectsArray<T> {
        $out = vec_of_objects_to_jobject_array(env, ($p).to_vec());
    };
    ($p:f_type, option = "NoNullAnnotations") => "swig_f_type!(T) []";
    ($p:f_type, option = "NullAnnotations") => "@NonNull swig_f_type!(T, NoNullAnnotations) []";
);

foreign_typemap!(
    ($p:r_type) <'a, T: SwigForeignClass> Option<Vec<&'a T>> <= internal_aliases::JForeignObjectsArray<T> {
        $out = if !$p.inner.is_null() {
            let tmp = jobject_array_to_vec_of_refs(env, $p);
            Some(tmp)
        } else {
            None
        };
    };
);
