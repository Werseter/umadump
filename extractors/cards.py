from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ctypes_utils import C_Ptr
from game_structs.account import WorkItemDataObject, WorkPieceDataObject
from game_structs.cards import CardDataDictionaryEntry, SupportCardDataDictionaryEntry
from game_structs.collections import GenericDictionary
from game_structs.work_data_manager import WorkDataManagerObject
from json_encoders.cards import decode_card_data_dictionary, decode_support_card_dictionary
from logger import logger
from .common import ExtractorContext, ExtractorFingerprint, dictionary_fingerprint, first_object_fingerprint


def _item_cost_fingerprint(items: C_Ptr[WorkItemDataObject]) -> ExtractorFingerprint:
    """Track inventory membership and Money, not every item quantity or card's contents."""

    if not items:
        return "items", 0

    if not (dictionary_ptr := items.contents.fields.dataDic):
        return "items", 0
    dictionary = dictionary_ptr.contents

    MONEY_ITEM_ID = 59  # there is no enum, it's a const in GameDefine object
    money = dictionary.get(MONEY_ITEM_ID)
    balance = money.value.contents.fields.itemNum.value if money is not None and money.value else 0
    return "items", dictionary_fingerprint(dictionary), balance


@dataclass(frozen=True)
class SupportCardExtractionData:
    entries: GenericDictionary[SupportCardDataDictionaryEntry]
    viewer_id: int
    item_data: C_Ptr[WorkItemDataObject]

    def fingerprint(self) -> ExtractorFingerprint:
        return (
            "support_cards",
            self.viewer_id,
            dictionary_fingerprint(self.entries),
            first_object_fingerprint("first_entry", (entry.value for entry in self.entries)),
            _item_cost_fingerprint(self.item_data),
        )


def resolve_support_card_extraction_data(wdm: WorkDataManagerObject) -> Optional[SupportCardExtractionData]:
    """Resolve support-card entries pointer and dictionary sizes."""

    support_card_data_ptr = wdm.fields.supportCardData
    if not support_card_data_ptr:
        logger.warning("WorkDataManager.SupportCardData is null")
        return None

    dictionary_ptr = support_card_data_ptr.contents.fields.dataDic
    if not dictionary_ptr:
        logger.warning("WorkSupportCardData.dataDic is null")
        return None

    user = wdm.fields.userData
    if not user or not (viewer_id := user.contents.fields.viewerId.value):
        return None

    return SupportCardExtractionData(entries=dictionary_ptr.contents, viewer_id=viewer_id,
                                     item_data=wdm.fields.itemData)


def resolve_support_cards(context: ExtractorContext) -> Optional[SupportCardExtractionData]:
    return resolve_support_card_extraction_data(context.work_data_manager)


def extract_support_cards(data: SupportCardExtractionData) -> list[dict[str, object]]:
    support_cards = decode_support_card_dictionary(data)
    logger.info("Decoded %d support cards", len(support_cards))
    return support_cards


@dataclass(frozen=True)
class CardDataExtractionData:
    entries: GenericDictionary[CardDataDictionaryEntry]
    item_data: C_Ptr[WorkItemDataObject]
    piece_data: C_Ptr[WorkPieceDataObject]

    def fingerprint(self) -> ExtractorFingerprint:
        pieces = self.piece_data.contents.fields.pieceDic.contents
        return (
            "card_data",
            dictionary_fingerprint(self.entries),
            first_object_fingerprint("first_entry", (entry.value for entry in self.entries)),
            _item_cost_fingerprint(self.item_data),
            dictionary_fingerprint(pieces),
        )


def resolve_card_data_extraction_data(wdm: WorkDataManagerObject) -> Optional[CardDataExtractionData]:
    """Resolve chara/card-data entries pointer and dictionary sizes."""

    card_data_data_ptr = wdm.fields.cardData
    if not card_data_data_ptr:
        logger.warning("WorkDataManager.cardData is null")
        return None

    dictionary_ptr = card_data_data_ptr.contents.fields.dataDic
    if not dictionary_ptr:
        logger.warning("WorkCardData.dataDic is null")
        return None

    return CardDataExtractionData(entries=dictionary_ptr.contents, item_data=wdm.fields.itemData,
                                  piece_data=wdm.fields.pieceData)


def resolve_card_data(context: ExtractorContext) -> Optional[CardDataExtractionData]:
    return resolve_card_data_extraction_data(context.work_data_manager)


def extract_card_data(data: CardDataExtractionData) -> list[dict[str, object]]:
    cards = decode_card_data_dictionary(data)
    # game calls the owned character data "card" data, making a distinction between alternate costume variants this way
    logger.info("Decoded %d owned character entries", len(cards))
    return cards
