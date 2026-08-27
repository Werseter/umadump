from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from game_structs.cards import CardDataDictionaryEntry, SupportCardDataDictionaryEntry
from game_structs.collections import GenericDictionary
from game_structs.work_data_manager import WorkDataManagerObject
from json_encoders.cards import decode_card_data_dictionary, decode_support_card_dictionary
from logger import logger
from .common import ExtractorContext, ExtractorFingerprint, dictionary_fingerprint, first


@dataclass(frozen=True)
class SupportCardExtractionData:
    entries: GenericDictionary[SupportCardDataDictionaryEntry]

    def fingerprint(self) -> ExtractorFingerprint:
        if (first_entry := first(entry for entry in self.entries if entry.value)) is not None:
            _ = first_entry.value.contents.fields
        return (
            "support_cards",
            dictionary_fingerprint(self.entries),
            ("first_entry", first_entry.value.address if first_entry is not None else 0),
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

    return SupportCardExtractionData(entries=dictionary_ptr.contents)


def resolve_support_cards(context: ExtractorContext) -> Optional[SupportCardExtractionData]:
    return resolve_support_card_extraction_data(context.work_data_manager)


def extract_support_cards(data: SupportCardExtractionData) -> list[dict[str, object]]:
    support_cards = decode_support_card_dictionary(data)
    logger.info("Decoded %d support cards", len(support_cards))
    return support_cards


@dataclass(frozen=True)
class CardDataExtractionData:
    entries: GenericDictionary[CardDataDictionaryEntry]

    def fingerprint(self) -> ExtractorFingerprint:
        first_entry = first(entry for entry in self.entries if entry.value)
        if first_entry is not None:
            _ = first_entry.value.contents.fields
        return (
            "card_data",
            dictionary_fingerprint(self.entries),
            ("first_entry", first_entry.value.address if first_entry is not None else 0),
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

    return CardDataExtractionData(entries=dictionary_ptr.contents)


def resolve_card_data(context: ExtractorContext) -> Optional[CardDataExtractionData]:
    return resolve_card_data_extraction_data(context.work_data_manager)


def extract_card_data(data: CardDataExtractionData) -> list[dict[str, object]]:
    cards = decode_card_data_dictionary(data)
    # game calls the owned character data "card" data, making a distinction between alternate costume variants this way
    logger.info("Decoded %d owned character entries", len(cards))
    return cards
