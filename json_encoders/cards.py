"""JSON decoders for umadump output."""
from __future__ import annotations

from typing import Any, Optional, TYPE_CHECKING

from game_structs.cards import CardDataDictionaryEntry, HintLevelDictionaryEntry, SupportCardDataDictionaryEntry
from logger import logger
from .common import timestamp_to_str

if TYPE_CHECKING:
    from extractors.cards import CardDataExtractionData, SupportCardExtractionData


# ---------------------------------------------------------------------------
# Support card extraction
# ---------------------------------------------------------------------------

def _decode_support_card_entry(entry: SupportCardDataDictionaryEntry) -> Optional[dict[str, Any]]:
    if entry.hashCode < 0 or not entry.value:
        return None
    f = entry.value.contents.fields
    return {
        "viewer_id": 0,
        "support_card_id": f.supportCardId.value,
        "exp": f.exp.value,
        "limit_break_count": f.limitBreakCount.value,
        "favorite_flag": int(f.isFavoriteLock.value),
        "stock": f.stock.value,
        "possess_time": 0,
        "create_time": timestamp_to_str(f.createTime.value),
        "extra_data": {
            "level": f.level.value,
            "max_level": f.maxLevel.value,
            "best_training": f.bestTraining,
        }
    }


def decode_support_card_dictionary(data: SupportCardExtractionData) -> list[dict[str, Any]]:
    """Descend WorkDataManager -> WorkSupportCardData -> Dictionary<int, SupportCardData>."""
    result: list[dict[str, Any]] = []

    support_card_data_dict = data.entries
    logger.debug("SupportCard dictionary: count=%d", support_card_data_dict.fields.count)

    for entry in support_card_data_dict:
        decoded = _decode_support_card_entry(entry)
        if decoded is None:
            continue
        result.append(decoded)

    return result


# ---------------------------------------------------------------------------
# Chara/card extraction
# ---------------------------------------------------------------------------

def _decode_hint_level_dictionary_entry(entry: HintLevelDictionaryEntry) -> dict[str, int]:
    return {
        "skill_id": entry.key.value,
        "level": entry.value.value,
    }


def _decode_card_data_entry(entry: CardDataDictionaryEntry) -> dict[str, Any]:
    f = entry.value.contents.fields
    return {
        "card_id": f.cardId.value,
        "rarity": f.rarity.value,
        "talent_level": f.talentLevel.value,
        "create_time": timestamp_to_str(f.createTime.value),
        "skill_data_array": [
            _decode_hint_level_dictionary_entry(x) for x in f.hintLevelDic.contents
        ] if f.hintLevelDic else []
    }


def decode_card_data_dictionary(data: CardDataExtractionData) -> list[dict[str, Any]]:
    """Descend WorkDataManager -> WorkCardData -> Dictionary<int, CardData>."""
    result: list[dict[str, Any]] = []

    card_data_dict = data.entries
    logger.debug("CardData dictionary: count=%d", card_data_dict.fields.count)

    for entry in card_data_dict:
        decoded = _decode_card_data_entry(entry)
        result.append(decoded)

    return result
