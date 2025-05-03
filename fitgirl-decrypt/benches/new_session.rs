#![feature(test)]

extern crate test;
use test::Bencher;

#[cfg(feature = "ureq")]
#[bench]
fn ureq_new_session(b: &mut Bencher) {
    b.iter(|| ureq::Agent::new_with_defaults());
}

#[cfg(feature = "reqwest")]
#[bench]
fn reqwest_new_session(b: &mut Bencher) {
    b.iter(|| reqwest::Client::new());
}

#[cfg(feature = "nyquest")]
#[bench]
fn nyquest_new_session(b: &mut Bencher) {
    use std::hint::black_box;
    let _ = init_nyquest();

    b.iter(|| tokio_rt().block_on(black_box(nyquest::ClientBuilder::default().build_async())));
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
