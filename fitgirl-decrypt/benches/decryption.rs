#![feature(test)]

use fitgirl_decrypt::Paste;
use test::Bencher;

extern crate test;

#[bench]
pub fn decryption(b: &mut Bencher) -> fitgirl_decrypt::Result<()> {
    let paste = paste();
    let cipher_info = get_cipher_info()?;

    b.iter(|| paste.decrypt(&cipher_info));
    Ok(())
}

#[rstest::fixture]
pub fn paste() -> Paste<'static> {
    Paste::parse_url("https://paste.fitgirl-repacks.site/?225484ced69df1d1#SKYwGaZwZmRbN2fR4R9QQJzLTmzpctbDE7kZNpwesRW").unwrap()
}

#[cfg(any(feature = "ureq", feature = "reqwest", feature = "nyquest"))]
#[allow(unused)]
#[rstest::fixture]
pub fn get_cipher_info() -> fitgirl_decrypt::Result<fitgirl_decrypt::CipherInfo> {
    let _ = init_nyquest();

    let paste = paste();

    #[cfg(feature = "ureq")]
    return paste.request();
    #[cfg(feature = "reqwest")]
    return tokio_rt().block_on(paste.request_async());
    #[cfg(feature = "nyquest")]
    return tokio_rt().block_on(paste.request_async_ny());

    Err(fitgirl_decrypt::Error::IllFormedURL)
}

#[rstest::fixture]
fn init_nyquest() {
    nyquest_preset::register();
}

#[rstest::fixture]
fn tokio_rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}
