"""Retained gacha memory mapped to the corresponding history and exec API shapes."""
from __future__ import annotations

from collections.abc import Iterable
from itertools import islice
from typing import TypedDict

from ctypes_utils import C_Ptr
from game_structs.account import WorkItemDataObject, WorkUserDataObject
from game_structs.enums import GachaConsumptionType, ItemCategory
from game_structs.gacha import GachaConsumptionObject, GachaHistoryExecObject, GachaResultSetObject
from schema_validation import TransientRuntimeValidationError


# ---------------------------------------------------------------------------
# Explicit output schema for postprocessing validation
# ---------------------------------------------------------------------------

class GachaExecutionRecord(TypedDict):
    exec_history_id: int
    gacha_id: int
    gacha_card_type: int
    draw_type: int
    draw_num: int
    cost_id: int
    cost_count: int
    create_time: str


class GachaRewardRecord(TypedDict):
    exec_history_id: int
    disp_order: int
    card_type: int
    card_id: int
    piece_id: int
    common_item_category: int
    common_item_id: int
    convert_piece_num: int
    convert_common_item_num: int
    additional_piece_num: int


class GachaHistoryPayload(TypedDict):
    gacha_exec_history_array: list[GachaExecutionRecord]
    gacha_reward_history_array: list[GachaRewardRecord]


class GachaPullReward(TypedDict):
    card_type: int
    card_id: int
    piece_id: int
    common_item_category: int
    common_item_id: int
    convert_piece_num: int
    convert_common_item_num: int
    additional_piece_num: int
    new_flag: int
    win_prize: int


class GachaCoinInfo(TypedDict):
    fcoin: int
    coin: int


class GachaItemInfo(TypedDict):
    item_type: int
    item_id: int
    item_num: int


class GachaLimitItemInfo(TypedDict):
    gacha_id: int
    num: int
    converted_item_num: int


class GachaBalanceState(TypedDict):
    """Post-draw balances of the in-game jewels or tickets used."""
    coin_info: GachaCoinInfo | None
    item_list: list[GachaItemInfo]


class GachaExecutionDetails(TypedDict):
    """Client context, with the last API header's exact Unix timestamp in seconds."""
    draw_type: int
    cost_id: int
    cost_count: int
    last_response_server_time: int


class GachaExecPayload(TypedDict):
    gacha_result_list: list[GachaPullReward]
    bonus_item_array: list[GachaItemInfo]
    reward_summary_info: dict[str, object]
    item_list: list[GachaItemInfo]
    coin_info: GachaCoinInfo | None
    limit_item_info: GachaLimitItemInfo
    extra_data: GachaExecutionDetails


# ---------------------------------------------------------------------------
# Encoder definitions
# ---------------------------------------------------------------------------

def gacha_history_payload(executions: Iterable[GachaExecutionRecord], rewards: Iterable[GachaRewardRecord]) \
        -> GachaHistoryPayload:
    # group executions by card type, newest first within each group.
    # reward array instead follows history ID and display order ascending.
    ordered_executions = sorted(executions, key=lambda row: (row['gacha_card_type'], -row['exec_history_id']))
    return GachaHistoryPayload(
            gacha_exec_history_array=ordered_executions,
            gacha_reward_history_array=sorted(rewards, key=lambda row: (row['exec_history_id'], row['disp_order'])),
    )


def decode_gacha_history(items: Iterable[C_Ptr[GachaHistoryExecObject]]) -> GachaHistoryPayload:
    executions: list[GachaExecutionRecord] = []
    rewards: list[GachaRewardRecord] = []
    for item in items:
        fields = item.contents.fields
        executions.append(GachaExecutionRecord(
                exec_history_id=fields.execHistoryId,
                gacha_id=fields.gachaId,
                gacha_card_type=fields.cardType,
                draw_type=fields.drawType,
                draw_num=fields.drawNum,
                cost_id=fields.costId,
                cost_count=fields.costCount,
                create_time=fields.createTime.value,
        ))
        for reward in fields.rewardArray:
            row = reward.contents.fields
            rewards.append(GachaRewardRecord(
                    exec_history_id=row.execHistoryId,
                    disp_order=row.dispOrder,
                    card_type=row.cardType,
                    card_id=row.cardId,
                    piece_id=row.pieceId,
                    common_item_category=row.commonItemCategory,
                    common_item_id=row.commonItemId,
                    convert_piece_num=row.convertPieceNum,
                    convert_common_item_num=row.convertCommonItemNum,
                    additional_piece_num=row.additionalPieceNum,
            ))
    return gacha_history_payload(executions, rewards)


def decode_gacha_execution(consumption: GachaConsumptionObject, draw_count: int,
                           server_time: int) -> GachaExecutionDetails:
    fields = consumption.fields
    tickets = fields.itemType in (GachaConsumptionType.SingleTicket, GachaConsumptionType.MultiTicket)
    return GachaExecutionDetails(
            draw_type=fields.drawType,
            cost_id=fields.itemId if tickets else 0,
            cost_count=draw_count if fields.itemType == GachaConsumptionType.SingleTicket else fields.cost,
            last_response_server_time=server_time,
    )


def decode_gacha_balances(consumption: GachaConsumptionObject, user: C_Ptr[WorkUserDataObject],
                          items: C_Ptr[WorkItemDataObject]) -> GachaBalanceState:
    """Read post-draw balances for the in-game currency or tickets used.

    WorkDataUtil.SetGachaExecResponse updates these account objects before the
    matching ExecutionResult is published. They are current balances, not a
    separately retained copy of the response.
    """
    fields = consumption.fields
    state = GachaBalanceState(coin_info=None, item_list=[])
    if fields.itemType in (GachaConsumptionType.SingleTicket, GachaConsumptionType.MultiTicket):
        if not items or not (dictionary := items.contents.fields.dataDic):
            raise TransientRuntimeValidationError('Gacha ticket balance is unavailable')
        remaining = 0
        if (entry := dictionary.contents.get(fields.itemId)) is not None:
            item = entry.value.contents.fields
            if item.itemId.value != entry.key:
                raise TransientRuntimeValidationError('Gacha ticket identity changed')
            remaining = item.itemNum.value
        state['item_list'].append(GachaItemInfo(item_type=ItemCategory.GACHA_TICKET, item_id=fields.itemId,
                                                item_num=remaining))
    else:
        if not user or not (currency := user.contents.fields.carrotStone):
            raise TransientRuntimeValidationError('Gacha jewel balance is unavailable')
        coins = currency.contents.fields
        state['coin_info'] = GachaCoinInfo(fcoin=coins.freeCoin.value, coin=coins.chargeCoin.value)
    return state


def decode_gacha_pull(result: GachaResultSetObject, balances: GachaBalanceState,
                      consumption: GachaConsumptionObject, server_time: int) -> GachaExecPayload:
    fields = result.fields
    draw_count = fields.drawCount
    rewards: list[GachaPullReward] = []
    prizes = fields.prizeResultArray.span()
    for order, pointer in enumerate(islice(fields.cardResultArray, draw_count)):
        if not pointer:
            raise TransientRuntimeValidationError('Gacha card result is not initialized')

        card = pointer.contents.fields
        if not card.cardId or not card.convertPiece or not card.convertItem:
            raise TransientRuntimeValidationError('Gacha card rewards are not initialized')

        pieces = card.convertPiece.contents.fields
        common = card.convertItem.contents.fields
        if card.order != order:
            raise TransientRuntimeValidationError('Gacha card result order is incomplete')

        prize = prizes[order] if order < len(prizes) else None
        rewards.append(GachaPullReward(
                card_type=card.cardType,
                card_id=card.cardId,
                piece_id=pieces.itemId,
                common_item_category=common.itemCategory,
                common_item_id=common.itemId,
                convert_piece_num=0,
                convert_common_item_num=common.itemNum,
                additional_piece_num=pieces.itemNum,
                new_flag=int(card.isNew),
                win_prize=prize.contents.fields.winPrize if prize else 0,
        ))
    if len(rewards) != draw_count:
        raise TransientRuntimeValidationError('Gacha card result order is incomplete')
    points = fields.limitPointResult.contents.fields
    coins = balances['coin_info']
    return GachaExecPayload(
            gacha_result_list=rewards,
            bonus_item_array=[],  # The processed result does not retain these complete response sections.
            reward_summary_info={},
            item_list=[GachaItemInfo(**item) for item in balances['item_list']],
            coin_info=GachaCoinInfo(**coins) if coins is not None else None,
            limit_item_info=GachaLimitItemInfo(gacha_id=points.gachaId, num=points.after, converted_item_num=0),
            extra_data=decode_gacha_execution(consumption, draw_count, server_time),
    )
