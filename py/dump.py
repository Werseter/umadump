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
data_parts = {}


def on_message(message, data):
    message_type = message.get("type")
    match message_type:
        case "send":
            payload = message.get("payload")
            match payload:
                case "veteran_data":
                    print("Received veteran data...")
                    data_parts["veteran_data"] = data
                case "veteran_extra_data":
                    print("Received veteran extra data...")
                    data_parts["veteran_extra_data"] = data
                case _:
                    print(f"Unknown payload: {payload}")
            if "veteran_data" in data_parts and "veteran_extra_data" in data_parts:
                print("Both data parts received, merging and extracting...")
                extract_veteran_data()
        case "error":
            print(message.get('stack'))
        case _:
            print(f"Unknown message type: {message_type}")


def extract_veteran_data():
    try:
        with open("veteran_data.msgpack", "wb+") as f:
            f.write(data_parts["veteran_data"])

        with open("veteran_extra_data.msgpack", "wb+") as f:
            f.write(data_parts["veteran_extra_data"])

        veteran_data = msgpack.loads(data_parts["veteran_data"])
        veteran_extra_data = msgpack.loads(data_parts["veteran_extra_data"])

        # Merge lists of dicts based on 'trained_chara_id'
        merged = []
        for item in veteran_data:
            chara_id = item['trained_chara_id']
            extra = next((x for x in veteran_extra_data if x['trained_chara_id'] == chara_id), {})
            merged_item = {**item, **extra}
            merged.append(merged_item)

        with open("umadump_data.json", "w+") as f:
            f.write(json.dumps(merged, indent=2))
    except Exception:
        raise
    else:
        global success
        success = True

script = session.create_script(r"""
//                                  'B3 trained_chara_array'
const trainedCharaPattern =         'B3 74 72 61 69 6E 65 64 5F 63 68 61 72 61 5F 61 72 72 61 79';
//                                  'BC trained_chara_favorite_array'
const trainedCharaFavoritePattern = 'BC 74 72 61 69 6E 65 64 5F 63 68 61 72 61 5F 66 61 76 6F 72 69 74 65 5F 61 72 72 61 79';
//                                  'BF room_match_entry_chara_id_array'
const roomMatchEntryPattern =       'BF 72 6F 6F 6D 5F 6D 61 74 63 68 5F 65 6E 74 72 79 5F 63 68 61 72 61 5F 69 64 5F 61 72 72 61 79'

function findPayload(startPattern, endPattern, tag) {
    const ranges = Process.enumerateRanges({protection: "r--", coalesce: true});
    for (const range of ranges) {
        const startResults = Memory.scanSync(range.base, range.size, startPattern);
        for (const startResult of startResults) {
            const startAddress = startResult.address.add(startResult.size);
            const startDiff = startAddress - range.base;
            const endResults = Memory.scanSync(startAddress, range.size - startDiff, endPattern);
            for (const endResult of endResults) {
                const endAddress = endResult.address;
                const endDiff = endAddress - startAddress;
                send(tag, startAddress.readByteArray(endDiff));
                return;
            }
        }
    }
}

findPayload(trainedCharaPattern, trainedCharaFavoritePattern, "veteran_data");
findPayload(trainedCharaFavoritePattern, roomMatchEntryPattern, "veteran_extra_data");
""")
script.on("message", on_message)
script.load()

if success:
    print("Successfully extracted data to 'umadump_data.json")
else:
    print("Failed to extract data")
