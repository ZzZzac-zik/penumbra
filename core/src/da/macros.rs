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

