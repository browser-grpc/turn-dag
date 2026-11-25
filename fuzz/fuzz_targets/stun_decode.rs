// cargo fuzz run stun_decode -- -max_total_time=60
#![no_main]
use libfuzzer_sys::fuzz_target;
use turn_dag_turn::wire::{decode_channel_data, StunMessage};

fuzz_target!(|data: &[u8]| {
    let _ = StunMessage::decode(data);
    let _ = decode_channel_data(data);
});
