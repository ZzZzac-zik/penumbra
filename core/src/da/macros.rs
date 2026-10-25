/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2026 Shomy
*/
macro_rules! exploit {
    ($exploit:ty, $proto:expr, $port:expr, $da:expr) => {{
        #[cfg(feature = "exploits")]
        {
            if !$proto.patched {
                let mut exploit = <$exploit>::default();

                if let Ok(result) = <$exploit as $crate::exploit::Exploit<Self, P>>::run(
                    &mut exploit,
                    $proto,
                    $port,
                    $da,
                ) {
                    $proto.patched = result;
                }
            }
        }
    }};
}

macro_rules! dump_preloader {
    ($proto:expr, $port:expr, $da1_addr:expr) => {{
        #[cfg(feature = "exploits")]
        if $proto.pl.is_empty()
            && $crate::port::MtkPort::connection_type(&*$port) == $crate::port::ConnectionType::Brom
        {
            $proto.pl = $crate::da::macros::dump_preloader($port, $da1_addr);
        }
    }};
}

#[cfg(feature = "exploits")]
pub(crate) fn dump_preloader<P: crate::port::MtkPort>(port: &mut P, da1_addr: u32) -> Vec<u8> {
    use hacc::TryRead;
    use hacc::gfh::{GfhFileInfo, GfhFileType};
    use log::info;

    use crate::port::{MAX_TIMEOUT, MIN_TIMEOUT};
    use crate::preloader::PlProtocol;

    /* Arbitrary size based on nothing other than hopes and dreams
     * NOTE: If we ever die in the middle of dumping, this is the issue!!!
     */
    const CHUNK_SZ: usize = 0x2000;

    let mut read = |addr: u32, buf: &mut [u8]| {
        port.set_timeout(MAX_TIMEOUT).ok();
        let status = PlProtocol::new(port).read32(addr, buf.len(), buf);
        port.set_timeout(MIN_TIMEOUT).ok();

        // BROM protocol is BE, but we need the preloader in LE for parsing it.
        buf.chunks_exact_mut(4).for_each(<[u8]>::reverse);

        status.is_ok()
    };

    let mut buf = vec![0u8; CHUNK_SZ];

    if !read(da1_addr, &mut buf) {
        return vec![];
    }

    let Some((off, total)) = buf.chunks_exact(4).enumerate().find_map(|(i, word)| {
        if !word.starts_with(b"MMM") {
            return None;
        }

        let gfh = GfhFileInfo::try_read(&buf[i * 4..]).ok()?;
        let total = gfh.file_len();

        (gfh.file_type() == GfhFileType::ArmBl).then_some((i * 4, total))
    }) else {
        return vec![];
    };

    let addr = da1_addr + off as u32;

    info!("Found preloader in SRAM at 0x{addr:08X} (0x{total:X} bytes), dumping...");

    buf.drain(..off);

    let current = buf.len();

    if total > current {
        buf.resize(current + (total - current).next_multiple_of(4), 0);

        if !read(addr + current as u32, &mut buf[current..]) {
            return vec![];
        }
    }

    buf.truncate(total);

    info!("Dumped preloader from SRAM at 0x{addr:08X} (0x{total:X} bytes)");

    buf
}
