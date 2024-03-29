// SPDX-FileCopyrightText: © 2020 EteSync Authors
// SPDX-License-Identifier: LGPL-2.1-only
#![allow(dead_code)] // some test crates do not use all of these constants

use std::env;

pub fn test_url() -> String {
    let server = env::var("ETEBASE_TEST_HOST").expect("Set ETEBASE_TEST_HOST to run tests");
    format!("http://{}", server)
}

#[allow(non_snake_case)]
pub struct TestUser {
    pub username: &'static str,
    pub email: &'static str,
    pub password: &'static str,
    pub pubkey: &'static str,
    pub encryptedContent: &'static str,

    pub loginPubkey: &'static str,
    pub key: &'static str,
    pub salt: &'static str,

    pub storedSession: &'static str,
}

#[allow(non_upper_case_globals)]
pub const sessionStorageKey: &str = "YA0cMVJ9Q_SKYJCvKNni9y13vf62rEIq8M6kjtT14b4";

pub const USER: TestUser = TestUser {
  username: "test_user",
  email: "test@localhost",
  password: "SomePassword",
  pubkey: "CXNdzeU6FgHz9ei64wJbKDhHc0fkoJ1p_c8zGuFeuGA",
  encryptedContent: "wjRGC2jhqYdtF7lO1aS2I5r8gaWx4mZR19_lMZeoNZVU3HbBTqlFC5zZkN-NOO-4cDPZk2xk27GspPLHkOH59-Jk5fAY5hKFT8Vdp0jSgBvKOww-zXXlKfzhkjrReyUSsBwra_NAxGg",

  loginPubkey: "A9K94qEAqMm_yrt0wXKwG6H7DDimFIxaRqCpKRrOSuI",
  key: "Eq9b_rdbzeiU3P4sg5qN24KXbNgy8GgCeC74nFF99hI",
  salt: "6y7jUaojtLq6FISBWPjwXTeiYk5cTiz1oe6HVNGvn2E",

  storedSession: "gqd2ZXJzaW9uAa1lbmNyeXB0ZWREYXRhxQGmmvZjsltGTbmbHECPtUBlTgICvtJHKHp246hnKKiDeJL90CrIOPzjRW6mQMDX0SnQ8S32YEVLS2Ji5jzVfZOkyWzePAeSZmDpUxZd8N5WJ0BiuMKauG9UvXzdAGgVAVH9YA3dzPbAZUtpoU2W94eqbupPCEUsjraLnLFW9g2UVrh35z4OW9QoC_0vgzqigpWySkTdJ_FjmQqalbuQF9CaTFJcngMnBy7uos4tKw53RawDQ_EdwuRQLJrVGP-9zQKzyi-Y5X_8eWImGcjHYZvLbN6O0uDxEDfcg0dQGaBB7YV94akSKIjPRHebvXYoPSjI-r0YkA9Q_-tiaGxSwIFq-uVgWzOX9tq4dXsVP-2QffhV8Bx1hUHTHOyd6TCfEqQ3nWWaLsqA9yAoDg-XAPXHVffFwJ5b3accJU_Y5H8_w6PmbBdrVFyN7lP6JB6yGBDs3gpT4osNwet1rRR_ueERr1ThSZcqdCwjfhOTZq0p5R3SAnzAnUJo0LUUBkuzNGeMCSlIPJgE4HjOWXgLUYxZOlbDIN6yHp4SGIiAepSGOUrcjmRCQaA",
};

pub const USER2: TestUser = TestUser {
  username: "test_user2",
  email: "test2@localhost",
  password: "SomePassword",
  pubkey: "QOZOIEUx2aSnEvrubiHxQ8Tf2UBw6eLea778H0-Bp3g",
  encryptedContent: "aomaCuUO5cYXPPxo7SdnvXqBUyqfgx-Hz9YK87e2R7CsfoxzQi1MJGLOfol7S2xXFUmIfSeQLr2Tq4BUBIkitHipDefmr73TP9gV3n-unORW0Vzw0zwpv2I8Aftf2O__DlGk9WfN_NA",

  loginPubkey: "h6tXrc783wSW3-TfnI5qg1teJbN5bQRcDE1fjZQ9Y08",
  key: "AWXkhEFuf_vKquq-vTgHoYRu9NXr0z4ZeScwaLSgoT4",
  salt: "xXfZM3DEiBNqL0pjfGgZSbTU82w9eD1UXUd54LuwMrU",

  storedSession: "gqd2ZXJzaW9uAa1lbmNyeXB0ZWREYXRhxQGozXNEXNXVzqw02Kh0aasRFAQiqxRxsNidJM1oHx0ng0GhNOTZ_jhdGEAx3SF1DTip3jFj_y9T6lqMrKS7vd5qjAcHWgueUExYNAHu6Mugx75lYiJbXhIX58KdFpqIZt49PX7rrD7ObyDikYnNFHRhO3TN_hhhOROahVNQCdtZurNsSnziHNgPAUZz_UIPBjDu0G5DHIPRaL4CQ0AaaiqJ-B4yURm-ygBmjV-m8jw8JA7KTPdwqY4Oe_dhdu3iQAZreRnI2R6eHybf2RjTXcLqKjIEMiFL7yR61pNV0p3hAtm8I3L8rX0BhpxrxmfdOrWyba4hJIGXxhFim8K-w5UrU8n21bGTij-xArXpIonT1GCd3YBJrgEH65sym0ED4n4gUiMqL3JT81II1ttlcywuSWHEH5wN6JPI59APe3aLQinDKe-cH2-4HHQJ5hRoJVzJiugLLnHAUJxbLOLv2QCpIpuSRhB0zCmZMTeq8KK5ZyrsanEZdSNf_UkD6_58TkdVba7f_l3LOSAA5-NsQeehpkf80t2xccVN7hyKEHNvZyDsX8VieKpAZQ",
};
