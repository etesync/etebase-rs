use flapigen::{JavaConfig, LanguageConfig};
use std::{env, path::Path};

fn main() {
    env_logger::init();
    let out_dir = env::var("OUT_DIR").unwrap();
    let in_src = Path::new("src").join("java_glue.rs.in");
    let out_src = Path::new(&out_dir).join("java_glue.rs");
    //ANCHOR: config
    let swig_gen = flapigen::Generator::new(LanguageConfig::JavaConfig(
        JavaConfig::new(
            Path::new("client")
                .join("src")
                .join("main")
                .join("java")
                .join("com")
                .join("etebase")
                .join("client"),
            "com.etebase.client".into(),
        )
        .use_null_annotation_from_package("androidx.annotation".into()),
    ))
    .merge_type_map("typemaps", include_str!("src/jni_typemaps.rs"))
    .remove_not_generated_files_from_output_directory(true)
    .rustfmt_bindings(true);
    //ANCHOR_END: config
    swig_gen.expand("android bindings", &in_src, &out_src);
    println!("cargo:rerun-if-changed={}", in_src.display());
}
