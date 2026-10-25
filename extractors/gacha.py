"""Current gacha results and open history-dialog sources."""
from __future__ import annotations

from dataclasses import dataclass

from ctypes_utils import C_Ptr
from gacha_archive import GachaCapture
from game_structs.enums import GachaExecutionType
from game_structs.gacha import (DialogGachaHistoryObject, GachaExecutionResultObject, GachaHistoryExecObject,
                                GachaResultSetObject, GachaResultTempDataObject)
from game_structs.ui import DialogCommonBaseObject, DialogManagerObject, SceneManagerObject
from json_encoders.gacha import decode_gacha_balances, decode_gacha_history, decode_gacha_pull
from logger import logger
from schema_validation import (RuntimeValidatableIl2CppClassManager, TransientContainerStateError,
                               TransientRuntimeValidationError)
from .common import (ExtractorContext, ExtractorFingerprint, list_pointer_fingerprint, object_array_fingerprint,
                     pointer_fingerprint)


@dataclass(frozen=True)
class GachaLiveSources:
    buffer: C_Ptr[GachaResultTempDataObject]
    resolved_pair: tuple[int, int]
    last_response_server_time: int

    @staticmethod
    def _is_execution_view(manager: SceneManagerObject) -> bool:
        """Exclude cached pulls after their animation/result views have been left."""
        if not (controller := manager.fields.currentViewController):
            return False
        if not (klass := controller.contents.klass):
            return False
        view = klass.contents
        return view.name.as_string in ('GachaMainViewController', 'GachaResultViewController')

    @staticmethod
    def _execution_is_ready(execution: GachaExecutionResultObject) -> bool:
        fields = execution.fields
        if fields.executionType != GachaExecutionType.Normal or not fields.executable:
            return False
        executable = fields.executable.contents.fields
        banner_id = executable.parentGachaId
        return bool(executable.consumption and banner_id and fields.parentGachaId == banner_id)

    @staticmethod
    def _result_matches_execution(execution: GachaExecutionResultObject, result: GachaResultSetObject) -> bool:
        outcome = result.fields
        if not outcome.limitPointResult or not outcome.drawCount:
            return False
        source = execution.fields.gachaData
        if not source or source.address != outcome.gachaData.address:
            return False
        capacity = len(outcome.cardResultArray)
        if not 1 <= outcome.drawCount <= capacity:
            raise TransientContainerStateError('Gacha results', outcome.drawCount,
                                               outcome.cardResultArray.address, capacity)
        return True

    @classmethod
    def _resolve_ready_pair(cls, buffer: GachaResultTempDataObject) -> tuple[int, int] | None:
        retained = buffer.fields
        execution, result = retained.executionResult, retained.resultSet
        if not execution or not result:
            return None
        published = execution.contents
        if not cls._execution_is_ready(published):
            return None
        if not cls._result_matches_execution(published, result.contents):
            return None
        return execution.address, result.address

    @classmethod
    def from_context(cls, context: ExtractorContext) -> GachaLiveSources | None:
        if not cls._is_execution_view(context.scene_manager):
            return None
        source = context.temp_data
        if not (buffer := source.fields.gachaResult):
            return None
        pair = cls._resolve_ready_pair(buffer.contents)
        if pair is None:
            return None
        return cls(buffer, pair, source.fields.serverTime.value)

    def read_pair(self) -> tuple[GachaExecutionResultObject, GachaResultSetObject]:
        """Require fresh resolution and timestamp sampling when either pointer changes."""
        buffer = self.buffer.contents.fields
        execution, result = buffer.executionResult, buffer.resultSet
        if (execution.address, result.address) != self.resolved_pair:
            raise TransientRuntimeValidationError('Gacha execution/result pointers changed after resolution')
        return execution.contents, result.contents

    def fingerprint(self) -> ExtractorFingerprint:
        execution_object, result_object = self.read_pair()
        execution = execution_object.fields
        executable = execution.executable.contents.fields
        cost = executable.consumption.contents.fields
        result = result_object.fields
        points = result.limitPointResult.contents.fields
        cards = object_array_fingerprint('cards', result.cardResultArray)
        return (*self.resolved_pair, execution.executionType, executable.parentGachaId,
                cost.itemType, cost.itemId, cost.cost, cost.drawType, result.drawCount,
                points.gachaId, points.before, points.after, cards,
                object_array_fingerprint('prizes', result.prizeResultArray))


@dataclass(frozen=True)
class GachaHistorySources:
    dialog: C_Ptr[DialogGachaHistoryObject]

    @staticmethod
    def _validate_backlinks(history: DialogGachaHistoryObject, native_address: int, data_address: int) -> None:
        fields = history.fields
        if fields.m_CachedPtr.address != native_address:
            raise TransientRuntimeValidationError('History component wrapper changed')
        if fields.dialogData.address != data_address:
            raise TransientRuntimeValidationError('History dialog owner changed')

    @classmethod
    def _resolve_dialog(cls, dialog: DialogCommonBaseObject, expected: int) -> C_Ptr[DialogGachaHistoryObject] | None:
        """Find the history component and verify its native and dialog backlinks."""
        if not (data := dialog.fields.data) or not (contents := data.contents.fields.contentsObject):
            return None

        if not (native := contents.contents.fields.m_CachedPtr):
            return None

        if (game_object := native.contents).managed.address != contents.address:
            raise TransientRuntimeValidationError('Dialog GameObject wrapper changed')

        for entry in game_object.components():
            if not entry.component:
                continue

            component = entry.component.contents
            if component.owner.address != native.address or not component.managed:
                continue

            klass = component.managed.contents.klass
            if not RuntimeValidatableIl2CppClassManager.runtime_class_is_or_inherits_from(klass, expected):
                continue

            history = C_Ptr[DialogGachaHistoryObject](component.managed.address)
            cls._validate_backlinks(history.contents, entry.component.address, data.address)
            return history
        return None

    @classmethod
    def from_manager(cls, manager: DialogManagerObject) -> GachaHistorySources | None:
        """Follow DialogManager -> contents GameObject -> its managed history component."""
        if not (dialogs := manager.fields.dialogList):
            return None
        expected = RuntimeValidatableIl2CppClassManager.get_expected_type_metadata_handle(DialogGachaHistoryObject)
        if expected is None:
            return None
        for dialog in dialogs.contents:
            if dialog and (history := cls._resolve_dialog(dialog.contents, expected)) is not None:
                return cls(history)
        return None

    def fingerprint(self) -> ExtractorFingerprint:
        fields = self.dialog.contents.fields
        cards = fields.cardHistoryList
        supports = fields.supportCardHistoryList
        card_list = list_pointer_fingerprint(cards)
        support_list = list_pointer_fingerprint(supports)
        card: C_Ptr[GachaHistoryExecObject] | None = cards.contents.first() if cards else None
        support: C_Ptr[GachaHistoryExecObject] | None = supports.contents.first() if supports else None
        card_rewards = object_array_fingerprint('rewards', card.contents.fields.rewardArray) if card else None
        support_rewards = object_array_fingerprint('rewards', support.contents.fields.rewardArray) if support else None
        card_pointer = pointer_fingerprint(card) if card else ('ptr', 0)
        support_pointer = pointer_fingerprint(support) if support else ('ptr', 0)
        return (card_list, card_pointer, card_rewards), (support_list, support_pointer, support_rewards)


@dataclass(frozen=True)
class GachaExtractionData:
    viewer_id: int
    context: ExtractorContext
    live: GachaLiveSources | None
    history: GachaHistorySources | None

    def fingerprint(self) -> ExtractorFingerprint:
        return ('gacha',
                self.viewer_id,
                self.live.fingerprint() if self.live else None,
                self.history.fingerprint() if self.history else ())


def resolve_gacha_data(context: ExtractorContext) -> GachaExtractionData | None:
    wdm = context.work_data_manager
    user = wdm.fields.userData
    if not user or not (viewer_id := user.contents.fields.viewerId.value):
        return None
    live = GachaLiveSources.from_context(context)
    history = GachaHistorySources.from_manager(context.dialog_manager)
    if not (live or history):
        return None
    return GachaExtractionData(viewer_id, context, live, history)


def extract_gacha_data(data: GachaExtractionData) -> list[GachaCapture]:
    captures: list[GachaCapture] = []
    if data.history:
        history_dialog = data.history.dialog.contents.fields
        histories: dict[int, list[C_Ptr[GachaHistoryExecObject]]] = {}
        for source in (history_dialog.cardHistoryList, history_dialog.supportCardHistoryList):
            if source:
                for item in source.contents:
                    banner = item.contents.fields.gachaId
                    histories.setdefault(banner, []).append(item)
        for banner, items in sorted(histories.items()):
            captures.append(GachaCapture(data.viewer_id, banner, 'history', decode_gacha_history(items)))
    if data.live:
        execution, result = data.live.read_pair()
        executable = execution.fields.executable.contents
        consumption = executable.fields.consumption.contents
        wdm = data.context.work_data_manager.fields
        balances = decode_gacha_balances(consumption, wdm.userData, wdm.itemData)
        payload = decode_gacha_pull(result, balances, consumption, data.live.last_response_server_time)
        captures.append(GachaCapture(data.viewer_id, payload['limit_item_info']['gacha_id'], 'exec', payload))
    logger.info('Decoded %d gacha banner observations', len(captures))
    return captures
