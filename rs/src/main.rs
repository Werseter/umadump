use frida::{Frida, Message};
use std::{
    fs::{self, OpenOptions},
    iter::Map,
    sync::LazyLock,
};

static FRIDA: LazyLock<Frida> = LazyLock::new(|| unsafe { Frida::obtain() });

fn main() -> Result<(), &'static str> {
    let device_manager = frida::DeviceManager::obtain(&FRIDA);
    let device = device_manager.get_local_device().unwrap();
    let processes = device.enumerate_processes();
    let process = processes
        .iter()
        .find(|p| p.get_name() == "UmamusumePrettyDerby.exe")
        .unwrap();
    let session = device.attach(process.get_pid()).unwrap();
    if session.is_detached() {
        return Err("Session is detached");
    }
    let script_source = r#"
//                   '82 B3 trained_chara_array'
const startPattern = '82 B3 74 72 61 69 6E 65 64 5F 63 68 61 72 61 5F 61 72 72 61 79';
//                 '90 BF room_match_entry_chara_id_array'
const endPattern = '90 BF 72 6F 6F 6D 5F 6D 61 74 63 68 5F 65 6E 74 72 79 5F 63 68 61 72 61 5F 69 64 5F 61 72 72 61 79';

function findPayload() {
    const ranges = Process.enumerateRanges({protection: "rw-", coalesce: true});
    for (const range of ranges) {
        const startResults = Memory.scanSync(range.base, range.size, startPattern);
        for (const startResult of startResults) {
            const startAddress = startResult.address.add(startResult.size);
            const startDiff = startAddress - range.base;
            const endResults = Memory.scanSync(startAddress, range.size - startDiff, endPattern);
            for (const endResult of endResults) {
                const endAddress = endResult.address;
                const endDiff = endAddress - startAddress;
                send({type: "success"}, startAddress.readByteArray(endDiff+1));
                return;
            }
        }
    }
}

findPayload();
        "#;
    let mut script_option = frida::ScriptOption::default();
    let mut script = session
        .create_script(script_source, &mut script_option)
        .unwrap();

    let msg_handler = script.handle_message(Handler);
    if let Err(err) = msg_handler {
        panic!("{:?}", err);
    }

    script.load().unwrap();
    script.unload().unwrap();
    session.detach().unwrap();
    Ok(())
}

struct Handler;

impl frida::ScriptHandler for Handler {
    fn on_message(&mut self, message: &Message, msgpack_data: Option<Vec<u8>>) {
        let data: Vec<serde_json::Value> = rmp_serde::from_slice(&msgpack_data.unwrap()).unwrap();
        let json_data = serde_json::to_string_pretty(&data).unwrap();
        fs::write("data.json", json_data).unwrap();
    }
}
