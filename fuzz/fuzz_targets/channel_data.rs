// cargo fuzz run channel_data -- -max_total_time=60
#![no_main]
use libfuzzer_sys::fuzz_target;
use turn_dag_turn::wire::{decode_channel_data, encode_channel_data};

fuzz_target!(|data: &[u8]| {
    if data.len() >= 2 {
        let _ = encode_channel_data(u16::from_be_bytes([data[0], data[1]]), &data[2..]);
    }
    let _ = decode_channel_data(data);
});
