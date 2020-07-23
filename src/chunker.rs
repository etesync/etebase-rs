// SPDX-FileCopyrightText: © 2020 Etebase Authors
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * The rolling sum implementation is based on Rollsum from bup which is in turn based on rollsum from librsync:
 * https://github.com/bup/bup/blob/master/lib/bup/bupsplit.c
 * https://github.com/librsync/librsync/blob/master/src/rollsum.h
 *
 * We tried a few alternatives (see experiments/chunker/ for details) though this was by far the best one.
 *
 * The problem with using such a chunker is that it leaks information about the sizes of different chunks which
 * in turn leaks information about the original file (because the chunking is deterministic).
 * Therefore one needs to make sure to pad the chunks in a way that doesn't leak this information.
 */

const WINDOW_SIZE: u32 = 64;
const CHAR_OFFSET: u32 = 31;

pub struct Rollsum {
    s1: u32,
    s2: u32,
    window: [u8; WINDOW_SIZE as usize],
    wofs: usize,
}

impl Rollsum {
    pub fn new() -> Self {
        Self {
            s1: WINDOW_SIZE * CHAR_OFFSET,
            s2: WINDOW_SIZE * (WINDOW_SIZE - 1) * CHAR_OFFSET,
            window: [0; WINDOW_SIZE as usize],
            wofs: 0,
        }
    }

    pub fn update(&mut self, byte: u8) {
        self.rollsum_add(self.window[self.wofs], byte);
        self.window[self.wofs] = byte;
        self.wofs = (self.wofs + 1) % (WINDOW_SIZE as usize);
    }

    fn rollsum_add(&mut self, drop: u8, add: u8) {
        let add = add as u32;
        let drop = drop as u32;
        self.s1 = self.s1.wrapping_add(add.wrapping_sub(drop));
        self.s2 = self.s2.wrapping_add(self.s1.wrapping_sub(WINDOW_SIZE * (drop + CHAR_OFFSET)));
    }

    /**
     * Returns true if splitting is needed, that is when the current digest
     * reaches the given number of the same consecutive low bits.
     */
    pub fn split(&self, mask: u32) -> bool {
        self.s2 & mask == mask
    }
}
