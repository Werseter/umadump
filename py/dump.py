# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "frida",
#     "msgpack",
# ]
# ///
import frida
import msgpack
import json

session = frida.attach("UmamusumePrettyDerby.exe")

success = False


def on_message(message, data):
    try:
        with open("data.msgpack", "wb+") as f:
            f.write(data)

        data = msgpack.loads(data)
        with open("data.json", "w+") as f:
            f.write(json.dumps(data, indent=2))
    except Exception:
        raise
    else:
        global success
        success = True


script = session.create_script(r"""
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
                send("success", startAddress.readByteArray(endDiff+1));
                return;
            }
        }
    }
}

findPayload();
""")
script.on("message", on_message)
script.load()

if success:
    print("Successfully extracted data to 'data.json")
else:
    print("Failed to extract data")
