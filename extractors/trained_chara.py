from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from game_structs.collections import GenericDictionary
from game_structs.trained_chara import FavoriteDataDictionaryEntry, TrainedCharaDataDictionaryEntry
from game_structs.work_data_manager import WorkDataManagerObject
from json_encoders.trained_chara import decode_trained_chara_dictionary
from logger import logger
from .common import ExtractorContext, ExtractorFingerprint, dictionary_fingerprint, first


@dataclass(frozen=True)
class TrainedCharaExtractionData:
    entries: GenericDictionary[TrainedCharaDataDictionaryEntry]
    favorite_entries: GenericDictionary[FavoriteDataDictionaryEntry]

    def fingerprint(self) -> ExtractorFingerprint:
        first_entry = first(entry for entry in self.entries if entry.value)
        first_favorite_entry = first(entry for entry in self.favorite_entries if entry.value)
        if first_entry is not None:
            _ = first_entry.value.contents.fields
        if first_favorite_entry is not None:
            _ = first_favorite_entry.value.contents.fields
        return (
            "trained_chara_data",
            dictionary_fingerprint(self.entries),
            ("first_entry", first_entry.value.address if first_entry is not None else 0),
            dictionary_fingerprint(self.favorite_entries),
            ("first_entry", first_favorite_entry.value.address if first_favorite_entry is not None else 0),
        )


def resolve_trained_chara_extraction_data(wdm: WorkDataManagerObject) -> Optional[TrainedCharaExtractionData]:
    """Resolve trained-chara entries pointer and dictionary sizes."""

    trained_chara_data_ptr = wdm.fields.trainedCharaData
    if not trained_chara_data_ptr:
        logger.warning("WorkDataManager.trainedCharaData is null")
        return None

    dictionary_ptr = trained_chara_data_ptr.contents.fields.dataDic
    if not dictionary_ptr:
        logger.warning("WorkTrainedCharaData.dataDic is null")
        return None

    fav_dictionary_ptr = trained_chara_data_ptr.contents.fields.favoriteDataDict
    if not fav_dictionary_ptr:
        logger.warning("WorkTrainedCharaData.favoriteDataDict is null")
        return None

    dictionary = dictionary_ptr.contents
    fav_dictionary = fav_dictionary_ptr.contents
    return TrainedCharaExtractionData(entries=dictionary, favorite_entries=fav_dictionary)


def resolve_trained_chara_data(context: ExtractorContext) -> Optional[TrainedCharaExtractionData]:
    return resolve_trained_chara_extraction_data(context.work_data_manager)


def extract_trained_chara_data(data: TrainedCharaExtractionData) -> list[dict[str, object]]:
    trained_charas = decode_trained_chara_dictionary(data)
    logger.info("Decoded %d trained chara entries", len(trained_charas))
    return trained_charas
