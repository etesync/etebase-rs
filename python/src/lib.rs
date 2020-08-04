#![allow(non_snake_case, unused)]

mod fixes {
    #[derive(Clone)]
    pub struct FetchOptions {
        limit: Option<usize>,
        stoken: Option<String>,
        iterator: Option<String>,
        prefetch: Option<etebase::PrefetchOption>,
        with_collection: Option<bool>,
    }

    impl FetchOptions {
        pub fn new() -> Self {
            Self {
                limit: None,
                stoken: None,
                iterator: None,
                prefetch: None,
                with_collection: None,
            }
        }

        pub fn limit(&mut self, limit: usize) {
            self.limit = Some(limit);
        }

        pub fn prefetch(&mut self, prefetch: etebase::PrefetchOption) {
            self.prefetch = Some(prefetch);
        }

        pub fn with_collection(&mut self, with_collection: bool) {
            self.with_collection = Some(with_collection);
        }

        pub fn iterator(&mut self, iterator: Option<&str>) {
            self.iterator = iterator.map(str::to_string);
        }

        pub fn stoken(&mut self, stoken: Option<&str>) {
            self.stoken = stoken.map(str::to_string);
        }

        pub fn to_fetch_options<'a>(&'a self) -> etebase::FetchOptions<'a> {
            let mut ret = etebase::FetchOptions::new();
            if let Some(limit) = self.limit {
                ret = ret.limit(limit);
            }
            if let Some(prefetch) = &self.prefetch {
                ret = ret.prefetch(prefetch);
            }
            if let Some(with_collection) = self.with_collection {
                ret = ret.with_collection(with_collection);
            }
            ret = ret.iterator(self.iterator.as_deref());
            ret = ret.stoken(self.stoken.as_deref());
            ret
        }
    }
}

include!(concat!(env!("OUT_DIR"), "/glue.rs"));
