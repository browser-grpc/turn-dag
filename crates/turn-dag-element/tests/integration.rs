use turn_dag_element::*;
use turn_dag_wallet::{HotWallet, PqWallet};
#[test]
fn wallet_signed_transfer_validates() {
    let w = HotWallet::generate(&[11u8; 32]).unwrap();
    let el = Element {
        id: ElementId::derive(b"chal", 1, &w.address()),
        owner: w.address(),
        status: ElementStatus::Unspent,
        mint_epoch: 0,
    };
    let tx = Transfer {
        element_id: el.id,
        from_pubkey: w.public_key().to_vec(),
        to_address: burn_sink_address(),
        nonce: 0,
    };
    let sig = w.sign(&tx.hash());
    assert!(HotWallet::verify(&tx.from_pubkey, &tx.hash(), &sig));
    assert_eq!(validate_transfer(Some(&el), &tx), Ok(()));
}
