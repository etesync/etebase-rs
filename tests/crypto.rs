// SPDX-FileCopyrightText: © 2020 Etebase Authors
// SPDX-License-Identifier: LGPL-2.1-only

mod common;

use common::USER;
use etebase::error::Result;
use etebase::test_helpers::crypto;
use etebase::utils::from_base64;
use std::convert::TryInto;

#[test]
fn derive_key() {
    etebase::init().unwrap();

    let derived = crypto::derive_key(
        from_base64(USER.salt).unwrap()[..16].try_into().unwrap(),
        USER.password,
    )
    .unwrap();
    let expected = from_base64(USER.key).unwrap();
    assert_eq!(&derived[..], &expected[..]);
}

#[test]
fn crypto_manager() {
    etebase::init().unwrap();

    let key = from_base64(USER.key).unwrap();
    let context = b"Col     ";
    let crypto_manager = crypto::CryptoManager::new(
        &key[0..32].try_into().unwrap(),
        context,
        etebase::CURRENT_VERSION,
    )
    .unwrap();
    let subkey = crypto_manager.derive_subkey(&[0; 32]).unwrap();

    assert_eq!(
        &subkey[..],
        from_base64("4w-VCSTETv26JjVlVlD2VaACcb6aQSD2JbF-e89xnaA").unwrap()
    );

    let hash = crypto_manager.calculate_mac(&[0; 32]).unwrap();
    assert_eq!(
        &hash[..],
        from_base64("bz6eMZdAkIuiLUuFDiVwuH3IFs4hYkRfhzang_JzHr8").unwrap()
    );

    let hash = crypto_manager.calculate_hash(&[0; 32]).unwrap();
    assert_eq!(
        &hash[..],
        from_base64("iesNaoppHa4s0V7QNpkxzgqUnsr6XD-T-BIYM2RuFcM").unwrap()
    );

    let clear_text = b"This Is Some Test Cleartext.";
    let cipher = crypto_manager.encrypt(clear_text, None).unwrap();
    let decrypted = crypto_manager.decrypt(&cipher, None).unwrap();
    assert_eq!(clear_text, &decrypted[..]);

    let clear_text = b"This Is Some Test Cleartext.";
    let (tag, cipher) = crypto_manager.encrypt_detached(clear_text, None).unwrap();
    let tag: &[u8; 16] = &tag[..].try_into().unwrap();
    let decrypted = crypto_manager.decrypt_detached(&cipher, tag, None).unwrap();
    assert_eq!(clear_text, &decrypted[..]);

    crypto_manager.verify(&cipher, tag, None).unwrap();

    let mut crypto_mac = crypto_manager.crypto_mac().unwrap();
    crypto_mac.update(&[0; 4]).unwrap();
    assert_eq!(
        crypto_mac.finalize().unwrap(),
        from_base64("y5nYZ75gDUna4bnaAHobXUlgQoTKOnueNW_KCYxcAg4").unwrap()
    );
}

#[test]
fn login_crypto_manager() {
    etebase::init().unwrap();

    let login_crypto_manager = crypto::LoginCryptoManager::keygen(&[0; 32]).unwrap();

    let msg = b"This Is Some Test Cleartext.";
    let signature = login_crypto_manager.sign_detached(msg).unwrap();
    let pubkey = login_crypto_manager.pubkey();
    assert!(login_crypto_manager
        .verify_detached(msg, &signature, pubkey.try_into().unwrap())
        .unwrap());
}

#[test]
fn box_crypto_manager() {
    etebase::init().unwrap();

    let box_crypto_manager = crypto::BoxCryptoManager::keygen(None).unwrap();
    let box_crypto_manager2 = crypto::BoxCryptoManager::keygen(None).unwrap();

    let msg = b"This Is Some Test Cleartext.";
    let cipher = box_crypto_manager
        .encrypt(msg, box_crypto_manager2.pubkey().try_into().unwrap())
        .unwrap();
    let decrypted = box_crypto_manager2
        .decrypt(&cipher[..], box_crypto_manager.pubkey().try_into().unwrap())
        .unwrap();
    assert_eq!(decrypted, msg);
}

#[test]
fn crypto_mac() {
    etebase::init().unwrap();

    let key = from_base64(USER.key).unwrap();

    let mut crypto_mac = crypto::CryptoMac::new(None).unwrap();
    crypto_mac.update(&[0; 4]).unwrap();
    crypto_mac.update_with_len_prefix(&[0; 8]).unwrap();
    assert_eq!(
        crypto_mac.finalize().unwrap(),
        from_base64("P-Hpzo86RG6Ps4R1gGXmQrzmdJC2OotqqreKmB8G45A").unwrap()
    );

    let mut crypto_mac = crypto::CryptoMac::new(Some(&key)).unwrap();
    crypto_mac.update(&[0; 4]).unwrap();
    crypto_mac.update_with_len_prefix(&[0; 8]).unwrap();
    assert_eq!(
        crypto_mac.finalize().unwrap(),
        from_base64("rgL6d_XDiBfbzevFdtktc61XB5-PkS1uQ1cj5DgfFc8").unwrap()
    );
}

#[test]
fn pretty_fingerprint() {
    etebase::init().unwrap();

    let pubkey = from_base64(USER.pubkey).unwrap();

    let fingerprint = crypto::pretty_fingerprint(&pubkey);
    assert_eq!(fingerprint, "45680   71497   88570   93128\n19189   84243   25687   20837\n47924   46071   54113   18789");
}

#[test]
fn deterministic_encrypt() -> Result<()> {
    etebase::init().unwrap();

    let key = from_base64(USER.key)?;

    let context = b"Col     ";
    let crypto_manager = crypto::CryptoManager::new(
        &key[0..32].try_into().unwrap(),
        context,
        etebase::CURRENT_VERSION,
    )
    .unwrap();

    // Deterministic encryption
    let clear_text = b"This Is Some Test Cleartext.";
    let cipher = crypto_manager
        .deterministic_encrypt(clear_text, None)
        .unwrap();
    let decrypted = crypto_manager.deterministic_decrypt(&cipher, None).unwrap();
    assert_eq!(clear_text, &decrypted[..]);

    let cipher2 = crypto_manager
        .deterministic_encrypt(clear_text, None)
        .unwrap();
    assert_eq!(cipher, cipher2);

    let precalc = vec![
        "Jp5B3loU3qoohgvlOuiYcbEI1JUhHzwfKsqRRvR_KZFQWvJFn07eHg",
        "yeX7EzjL43RCN89Ch5RBjWkmIj4GwFNgKJhKYEmbn0Crgey8ScixVzk",
        "wq1YkcgH4XEkjRPb8A93Si6hVUdzekkx3Zi_RghmbPrnvdKHFAEp1oNk",
        "kctDIpfaUOgcUl-2Xtr64DO7zq4UX_z0HdrwcfZBAErcONQkdUv2N0Y3zA",
        "fkbl5El2TqjHPnQxg2u4IGtvqTbOEL9OwpZY8e0F6FyZDcBm24L5suM85jI",
        "snmNhMLHUM8dkeIJPD5Yj9v4IC32fIz-qQ1B59pHHBPmY4bxN-G0EjEgPiBM",
        "K1yLz2KUtZxFEe9bMgbJrzLW5zblZGRu2bYPlkGftwXNExEhgA60Pyz8wop9Ag",
        "Ieyj3IiI3GQ8PMY8QbCUzt4ni-jOTEa1igG6_k70gSE16Nhj8u3PN2uUhoP4hfw",
        "vGRqKW8it-OoQYl5sAsQiuQI4oocINk85bkq9v74st7nuYV8Hfqu_thhdpYztlGW",
        "Nsi1q71WXgQ1m1Qw7qZAjVv3TKvZwV64tAMyIPIfuIvQde4v0TzGCjkVdykssYFRGA",
        "R_pAHkt07ZR7kjAdE9rER9bxHTwyJjIDt3z61vhsh3mkOE9fxHaq_9rIFDzhc8RwzpA",
        "Xo_CNDIxokmU5Qwx8A3_WVbnvuQylNFM-NKwAj6bHHETi7iJQAuhK0GuY3COTbIf7q7b",
        "idxPqtKGk4dIiScBs98T-y96UE10hH-6xIdc25WN-VvhPo1x9Kfe8fmPBGUGeUO1wovaYg",
        "JYNRpo0r1xVrXdD27sHblDwT1p75TmHGDZpFoXvQtoC21xOup42g7cIJcxJH3Ew_enhu1w4",
        "L5LEscfqPzWWpZ5A1ok-ymlSwlyleuF-KupfJMkF0QHvYi-0pk5416nni6Yv4NJgB4Qe4_5D",
        "EVy8E401Licx7Pjg_3YdC0Ei9xqtAqzFApm_gzA47-1SAZr7aJbwSuWQTVcTX-7pNquBLqtZ8A",
        "KQN3_3r8n7HvrNu7XGXAvpyQayrc9xErVP1fOzfCXUaUmrHNiiEwPfKk5s5O0OkiPHhbbdKBV0k",
        "AH3PrPmGu1bIK782H4HXq-OwY-lIa8vHdSVL1FyrbfLHvycEQftHMZU6_GHZhMNsRQs4XpkmljHZ",
        "dqVa0LN4ZADsz9Fzk5Jmve8aUJ4yxeiCmbSjEo-uhfsjBawSYlpNnpMe6VTJvcuja0eKPkvFimPJpg",
        "f7UIdICsvS4DUSFPGPkmtpqJiqFuzHx0qi4vxTtNrBu1V7hbT2NZceYo4FJY4eT37E2Im1juv2CdrV8",
        "6zpSAooPLr3VP4Vo5TuTu-H5-sucMe6H4GbkY8Np_Z5HBQEpvRXaPzLlEyTV8bTILZLdYX6lHDdW_cxp",
        "B34WgoV9X5WUFbxz7u1LsnSyjU9CNQZ5E-P-BaZjAN_AtM7InIUDcsqQciWdWx2H3TFU6B79wkOcxHyWbA",
        "2peH_bAKZ8wpI_vZjfoTcFUenAxjQCUfqVMY0THEF92KFiwJzp8g-wNssn2M0NBCAEZ_9aYWF5wcNFWOjOw",
        "5069CemejoWosspugqz4hN8nBEYlChw714tnt2wp8071jJ9S46I5cNilKHJRMLj2-aGZcizcQi4ihgjLP6QN",
        "ymfpIBHspNuU4DKyceUEtAiztOgBpmZyp70jjNcVylrRzDHBZC_gfX7lKRwrz9DieyosS7cU1EIe30-zGjtQXA",
        "w1MKV555BID3wRfHjj-X91UJ9-UaTvflOmH1fI9j5yeYkMr9I2comXG8utjZhsIctZnD6RNfNa7fqQ2OdnS7WJM",
        "s4c8WeKXZLQtovpTZhKAGgPl9Akt9MFyUvV5L-boDD53RJ2K8AJ6SlrVJ5UXJa-vueiLYr2LBrdDCIo1aAenEpay",
        "-f8e84MQWdS-494BTj2uTn8wDS00YIQCv53YCSEMPXRQvJus8We-dBfrY9MGKAYj5qzvWD2AhpNPamzDEBu2XqZoMg",
        "c-XbLLQqWN9gTx_B-gXof4fqyMi26jvXI2_v3RRuMK1Hraz1TYj3WnE5LRENqkv74sokPCAgjrK38p269gCGxuKzofM",
        "bTLj08EChb3UH2XBfwXbiYbHAQfnf2480Lj5GvAr2r9UZ5HxdcUS0e19Xkp0kHRYHoNiW7Lf10qTUq6UhfLG1RHfm910",
        "odlwQWwzuIVkrTsItYppK4VCRilMmwjURouls_qsfwOnEWnL6mkaLIkrC6xzI34oFztuNxYniyyb9QPJ9mAyIGwEHCGKIA",
        "XfRyxsqIpNpVYTKLQqttbool_y55nTCLU0FtpYwKHrM8qxa-cOA8GzL8jds2E7PiLjXl5Q1L_id6ycQzfdBQ7WafB4hnqqw",
        "XTZco0R8H3bHobcXJ9c0-8KTRz-sqJQTtqiTk42mLzk4IhJyxv0aqpLX2kKnC3TXCLKWFEYZ1GZfczjeRtUCTYvxxFxzJVSD",
        "thoiDEkUe_QB2Nr9r8V-6xOwvUMHX26CvfRR1OLSItT9CtkygyJbDdHiVFtXdE6illf1-LVpvMLWIxCdvCJHDNfI2-AeBmE4Qg",
        "lsRvZEJM8jg02hi-iZjU4oUaG3ShY97bybmSyupYRmdWR_Mq6yx-mMdHuJ0FLJJwSLOdC8HJl7w2SHGSjISFdq_wyZUpT96BKyg",
        "MUUww8zlee8WL7VXf9db2_yY2Pq4qP4upLO9rYkwqON6LoXG3MVOWvm-CA_jOhkaKbait2di6thqPzcKjcnTg6S8dqBcVaEOSRXG",
        "fL9P3em0q_YKn92Shu1kT0icbPLcTdNrrDcGvsSTpm1bphqGchBGp1zFhS298x0IjMgqRh9oR9iPvGP4VmVZJfPwWtRZKxPoOalbDA",
        "jWi6aNkZ3AKfXmziTtB2RlKQS9gn3FrEsObeBkkKpYg0NQZ3v1r4ctlCjNf9U-SDS7XqOoRji5ul9QSBRR52j54fT9xHAxL-rboumHs",
        "y4q20v0qNc8RtYVQVsNwm_Am1z0hx9xNjXjcNGKgH0ryMFWIGTxN_eexl_cc2g9leJMpzIqwBTUNy90yW0VlPUnWtrtP4g9Z4QeZrwM4",
        "r5HwVw_cxFger0iGhx-4bLXksarwRP3nDtnAb2syjBdYiJ9IirZ9L6rKK_tXD5cuaBwcZwsJ1ENDQ1VZzSeVYL5gpVEq_5fvmNObCDnEzw",
        "2J5nlC4PCF6NLrEsJvgXXTc_iQPX6mt30PCluL8vMCaTrpu5QvjtEcitLbd-mhLPiQh4V6nGbzLhDWZH3NXsfPcuVdASydJuRtqdazMhyfU",
        "T5QIIuRI38m6q0ZERuaTrNhGfhPVI2qpkguHNqJZNJiTXaAYv8_6ubjjnEUAZMCLkHja5MVO0l7EQLaEr9-8hH0PA-UvLNUasYUYDZQb0Jou",
        "9uGX6TgvOZnUF2158KJTEys_Ho9gNlDA2gC_im-Ag8uiULRjuYMJb4AzvFhonTqLVrUp6uncWXKcC2l1vaQ6ZYC2eZg-pIQtcizQGhx8NTEGsw",
        "rhZgQ-PQM96a857ECp8DgsSQuYLHkl7wKNGwD_ro61fFmNh0O6q2fNPuT4sQaGkK6m6l1yiGAkxUFZLvOplz60xGMjByBebH2FO4Jzi0-RLd4q8",
        "mb64LyC2TPOmtKtT0x5KgCiWmGxpTG1zwkaYez2-ahFNigLkH6HIsA8IU2ixv7hexJ9ER2EYz4PGuWMyyr6HAsbI2sE2mTckP5UIje-cF2i_mJFI",
        "4NoeQWukzqHqmIy9fb9Cow-Ll0OIvdUumMXO1kUed5DJguf4KoThpTnZstaDaS1XC52_-G5EOZbWHt-S4wMCJKq9v_sPqa3ICTxVqQw1ngqWktOlpw",
        "qPezqtNCH6bINVKJLULIEhf0nL5pQZRuikWJ1mta7L064fxX3kB0FDfWbhPp1EtzEH9LJY3FAxw_Uk0lU1FKVrfEwC6xsoKYe_XyovWzUak2N-FIXKE",
        "WxbGFiQOGOAKUQ9V7ME9tCibApQtzQ6h3Tq6FImQlbQeXBLhMKlJBLaB4EbozyrkKu31Ly-kYP4bjnTYN-brndzUwjcd8qpKur9P9KEKMdcwpJV5l-4t",
        "ZsTdFy5oVeZ96DHX8BP12kYnCCnoeX-rOXR-iWsWQF3NujWNsTipkuL4RcBHPSGQ4CI5VGjTe79_-qnWAWxsRR34nD3FH80N2c7Pq7YrISejB9GQeiaLNg",
        "jsorKAAeaexaPv_ACPQJDpgBEWhEMMztyhtPO1Ik3u9qijAmJEe21foDXGnZ2v8-cW_6kHA5bJj5atZ3beQ3NN56OgCsuZeHGJdQwW3UxjlodeRxQ-qwHrQ",
        "06gzf1gMtshvicAjfWlYih8bT0ZZ4xw8Sc5rO-UtRosyDJTzrUmBxgQGDu56RmJaH1sOQL6tu7Cg66MR0iYR6nOh6i1O90t_PgiwU9yBTEccnkmXV3qjpF0U",
        "2ZbXCb4M2xMexs1jiWGTou6zjJzxJp3kjfYc-Th_pqixIRK9EW0vHE648flV4UG1Qs791E1kA4MIWqoVoMccKKX0-RzHBlRnpMegs1pG8M8_Bfzzu8xAK63M5A",
        "tfJkxizYBpcirxxhj45_YPtTv30hXN15oaUvJvUGcUDCa8EKImVFU6d9MgnGGTwaRKYIq-CbMZrh3PY9O_DjZ81Y1ukQlzSKXOBwV3JBQNB0ndLo12r_XXUaFPg",
        "-5MpP_i_5PLst6d2QOsl4-oIU5QCgITDCzkyhhb2VHZQO6Qk4p0fsGzAg3znuikSeL-xIdAUrcpm9pM-cBGxroAALUgJnqLkI35WhiF32Zw6IV4_oYrl42rYH4q_",
        "wAHIWJEsmefqec6mnGNw5d9yr4QAph-8gAkZmc6pB7rhWDLnje4nIvFdcD3G4NgfOkghuo_6-jieoKzMTNrdWWyFyrq-bgp7F_OhvOCFFGjM43KhRhIDx5qsfUXXRw",
        "FjqUGdzYhkB9kne_GzHRLXTry8158WMz95YSwuQZQjhsEP9eTm-YFYGtvfwOsTCF7-_qyxsYtcXQs6NuJYyaEzwRgbjsGQPsRZz_dGncBHvdzQ9UPVIweNbdgfBGuRs",
        "vC8L1lCAPWPh5dzrKrzxlxmaHZdQLNJRyoZANjGlSYWz9ZW-yiJ8QnDQoUwI3WTrjIB5QpkapSqCbBrMZKkuGkK--2T8sgV_bPl0Nkue-oIlQfYywbCM73hApEjcCBxG",
        "XQi35b8zsvEg_FW64CuQfPUS4y_hKT-UvLB90hW0BoaoMRVCFSNJwdqN_xlOBKDfZ3UaF_0OCqIjZq6pOgER0RUgmnx9YaZ3VAwCZ_Y6NbgSGfO8ytv0QDp2LfdbZFKtbw",
        "pvS-qpn6XVs9Q-CXYWwUbjSGnVFHsO9R5zq0f5Ls11syaf5zJ8cct-R48QgEJignHMUTCu8ClTjnXE4iE4Bm5oYYEeY97sqj4P_pjrM5SjVZ2hGD40EoV0OFLNo-IdoDJf0",
        "MJAsZmWx9mPndWeoj4L5HmbebQEPngF-6FjvMVAO3q8CbO1943HMOxo5myfYMAXlAX7H0gsQV0Kk-rTrIVvAlmkRA5eElK7_ztz75tSG7sg7hXA-nkuXOWiPgmw-4ATmZlek",
        "hj0UQxVn8H70Qb6GxuEDRcuDcsLwZKXJUP5fGqoYl1fm53Msa9qQ4O5cGMp9p2yiylYg7Ys-zHPpHxCiBx-tuU-bFUvriaCR3eIMniM6RLQ1gnqB7D7dMwe1TddjPES8d5ysyA",
        "8KXkqEc9Q3xPmU6VyeUaXjhvWZGSLgLAaH-m2Ubp_gmN-vlduhkXzxciRHeT7jkUHvMt2JczD_gY4sn8Pn9-RPoy11VpDRzXDr9I-OMzNwqzt0OLnfBTDvBWPojTJTVrFRDaLzs",
        "idxFzEtY_FQ-dcY2MJ7WuIt_UmafJApFW1vPWAP6LnEIm2TahVqDGs93wgQs4kewWeBsVhjmtLCMH7IcNyavDa0yc9bzd5EhwHZwmVuc7TVo6TmsN3MiMg57Spq78Ur-2sCrwpwX",
        "wDkNMUPUFESxc0Kz0jqUrm6BnPu9OYOJn8VSMc_YjamfRkJi5CSHWZmv-Ps__dg5dwOR1gzIg56z4SUfyBSR9nVpF34DpgoFEs3E69B8GdnjANpTY6swRA2hGnue2jBzRTQrWjwYbA",
    ];

    let blocksize = 32;
    for i in 0..(blocksize * 2) {
        let buf = vec![60; i];
        let cipher = crypto_manager.deterministic_encrypt(&buf, None).unwrap();
        assert_eq!(from_base64(precalc[i]).unwrap(), cipher);
    }

    Ok(())
}
