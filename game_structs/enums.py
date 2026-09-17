from __future__ import annotations

from ctypes import c_uint8

from ctypes_utils import SafeIntEnum
from schema_validation import register_enum


# ---------------------------------------------------------------------------
# Game enums
# ---------------------------------------------------------------------------

@register_enum('Gallop::MasterSupportCardData.TrainingType')
class TrainingType(SafeIntEnum):
    Turf = 0
    Pool = 1
    Dirt = 2
    Slope = 3
    Study = 4
    Outing = 5
    Group = 6
    None_ = 7


@register_enum('Gallop::TrainingDefine.TrainingCommandId')
class TrainingCommandId(SafeIntEnum):
    None_ = 0
    Turf = 101
    Dirt = 102
    Slope = 103
    Pool = 105
    Study = 106
    Feed = 108
    Outing1 = 301
    Outing2 = 302
    Outing3 = 303
    OutingSea = 304
    OutingSpa = 305
    RaceEntry = 401
    SeaTraining1 = 601
    SeaTraining2 = 602
    SeaTraining3 = 603
    SeaTraining4 = 604
    SeaTraining5 = 605
    Holiday = 701
    Hospital = 801


@register_enum('Gallop::WorkTrainedCharaData.FavoriteData.FavoriteType')
class FavoriteType(SafeIntEnum):
    Default = 0
    Common01 = 1
    Common02 = 2
    Common03 = 3
    Common04 = 4
    Common05 = 5
    Common06 = 6
    Common07 = 7
    Common08 = 8
    ProperShort = 9
    ProperMile = 10
    ProperMiddle = 11
    ProperLong = 12
    ProperDirt = 13
    ProperFriend = 14


@register_enum('Gallop::TeamStadiumDefine.RoundResultType')
class RoundResultType(SafeIntEnum):
    None_ = 0
    Win = 1
    Lose = 2
    Draw = 3


@register_enum('Gallop::SingleModeScenarioTeamRaceDefine.TeamParameterRank')
class TeamParameterRank(SafeIntEnum):
    None_ = 0
    G = 1
    F = 2
    E = 3
    D = 4
    C = 5
    B = 6
    A = 7
    S = 8


@register_enum('Gallop::SingleModeScenarioTeamRaceDefine.TeamEditFlag')
class TeamEditFlag(SafeIntEnum):
    Invalid = 0
    On = 1
    Off = 2


@register_enum('Gallop::WorkTrainedCharaData.TrainedCharaData.UseType')
class TrainedCharaUseType(SafeIntEnum):
    NONE = 0
    RENTAL = 1
    GHOST = 2


@register_enum('Gallop::WorkTrainedCharaData.TrainedCharaData.SuccessionCharaPosition')
class SuccessionCharaPosition(SafeIntEnum):
    SELF = 1
    FIRST_1 = 10
    FIRST_2 = 20
    SECOND_1_1 = 11
    SECOND_1_2 = 12
    SECOND_2_1 = 21
    SECOND_2_2 = 22


@register_enum('Gallop::GameDefine.FinalTrainingRank')
class FinalTrainingRank(SafeIntEnum):
    NONE = 0
    G = 1
    G_PLUS = 2
    F = 3
    F_PLUS = 4
    E = 5
    E_PLUS = 6
    D = 7
    D_PLUS = 8
    C = 9
    C_PLUS = 10
    B = 11
    B_PLUS = 12
    A = 13
    A_PLUS = 14
    S = 15
    S_PLUS = 16
    SS = 17
    SS_PLUS = 18
    UG = 19
    UG1 = 20
    UG2 = 21
    UG3 = 22
    UG4 = 23
    UG5 = 24
    UG6 = 25
    UG7 = 26
    UG8 = 27
    UG9 = 28
    UF = 29
    UF1 = 30
    UF2 = 31
    UF3 = 32
    UF4 = 33
    UF5 = 34
    UF6 = 35
    UF7 = 36
    UF8 = 37
    UF9 = 38
    UE = 39
    UE1 = 40
    UE2 = 41
    UE3 = 42
    UE4 = 43
    UE5 = 44
    UE6 = 45
    UE7 = 46
    UE8 = 47
    UE9 = 48
    UD = 49
    UD1 = 50
    UD2 = 51
    UD3 = 52
    UD4 = 53
    UD5 = 54
    UD6 = 55
    UD7 = 56
    UD8 = 57
    UD9 = 58
    UC = 59
    UC1 = 60
    UC2 = 61
    UC3 = 62
    UC4 = 63
    UC5 = 64
    UC6 = 65
    UC7 = 66
    UC8 = 67
    UC9 = 68
    UB = 69
    UB1 = 70
    UB2 = 71
    UB3 = 72
    UB4 = 73
    UB5 = 74
    UB6 = 75
    UB7 = 76
    UB8 = 77
    UB9 = 78
    UA = 79
    UA1 = 80
    UA2 = 81
    UA3 = 82
    UA4 = 83
    UA5 = 84
    UA6 = 85
    UA7 = 86
    UA8 = 87
    UA9 = 88
    US = 89
    US1 = 90
    US2 = 91
    US3 = 92
    US4 = 93
    US5 = 94
    US6 = 95
    US7 = 96
    US8 = 97
    US9 = 98
    MIN = 1
    MAX = 98


@register_enum('Gallop::GameDefine.FactorRarity')
class FactorRarity(SafeIntEnum):
    NONE = 0
    RARE_1 = 1
    RARE_2 = 2
    RARE_3 = 3


@register_enum('Gallop::RaceDefine.RaceType')
class RaceType(SafeIntEnum):
    NONE = 0
    PvP = 1
    Tutorial = 2
    Story = 3
    StoryCondition = 4
    Champions = 5
    Single = 6
    SingleModeScenarioTeamRace = 7
    RoomMatch = 8
    Practice = 9
    Daily = 10
    TeamBuilding = 11
    Legend = 12
    ChallengeMatch = 13
    TeamStadium = 14
    Heroes = 16


@register_enum('Gallop::GameDefine.CardRarity')
class CardRarity(SafeIntEnum):
    NONE = 0
    Rare1 = 1
    Rare2 = 2
    Rare3 = 3
    Rare4 = 4
    Rare5 = 5


@register_enum('Gallop::HorseInitialLaneCalculator.InitialLaneType')
class InitialLaneType(SafeIntEnum):
    ExtraSpaceAfter9 = 1
    Equidistant = 2
    ExtraSpaceAfter14 = 3
    ExtraSpaceAfter8 = 4


@register_enum('Gallop::RaceDefine.Rotation')
class Rotation(SafeIntEnum):
    Right = 1
    Left = 2
    StraightRight = 3
    StraightLeft = 4


@register_enum('Gallop::RaceDefine.ResultBoardConditionType')
class ResultBoardConditionType(SafeIntEnum):
    Turf_None = 1
    Turf_Dirt = 2
    Dirt_None = 3
    Dirt_Turf = 4


@register_enum('Gallop::RaceDefine.CourseDistanceType')
class CourseDistanceType(SafeIntEnum):
    Short = 1
    Mile = 2
    Middle = 3
    Long = 4


@register_enum('Gallop::RaceDefine.TurfVisionType')
class TurfVisionType(SafeIntEnum):
    URA = 1
    NAU = 2
    Stand = 3


@register_enum('Gallop::RaceDefine.GroundCondition')
class RaceGroundCondition(SafeIntEnum):
    Good = 1
    Soft = 2
    Hard = 3
    Bad = 4


@register_enum('Gallop::RaceDefine.Weather')
class RaceWeather(SafeIntEnum):
    NONE = 0
    Sunny = 1
    Cloudy = 2
    Rainy = 3
    Snow = 4
    Max = 5
    Min = 0


@register_enum('Gallop::GameDefine.BgSeason')
class BgSeason(SafeIntEnum):
    NONE = 0
    Spring = 1
    Summer = 2
    Fall = 3
    Winter = 4
    CherryBlossom = 5
    Max = 6
    Min = 0


@register_enum('Gallop::RaceDefine.Time')
class RaceTime(SafeIntEnum):
    NONE = 0
    Morning = 1
    Daytime = 2
    Evening = 3
    Night = 4
    Max = 5
    Min = 0


@register_enum('Gallop::RaceDefine.RunningStyle', storage_type=c_uint8)
class RunningStyle(SafeIntEnum):
    None_ = 0
    Nige = 1
    Senko = 2
    Sashi = 3
    Oikomi = 4


@register_enum('Gallop::RaceDefine.RunningStyleEx')
class RunningStyleEx(SafeIntEnum):
    NONE = 0
    Oonige = 1


@register_enum('Gallop::RaceDefine.Motivation')
class RaceMotivation(SafeIntEnum):
    NONE = 0
    Min = 1
    Low = 2
    Middle = 3
    High = 4
    Max = 5


@register_enum('Gallop::RaceDefine.DefeatType')
class DefeatType(SafeIntEnum):
    Null = 0
    Win = 1
    Lose = 2
    RunningStyleMany = 3
    Temptaion = 4
    GutsOrder = 5
    Stamina = 6
    LastSpurtFalse = 7
    LastSpurtTargetSpeedDec = 8
    PassiveSkillNum = 9
    BlockFrontTime = 10
    Speed = 11
    ProperDistance = 12
    ProperGround = 13
    Motivation = 14


@register_enum('Gallop::ModelLoader.RaceRunningType')
class RaceRunningType(SafeIntEnum):
    Base = 1
    Pitch = 2
    Stride = 3


@register_enum('Gallop::RaceDefine.ProperGrade')
class ProperGrade(SafeIntEnum):
    Null = 0
    G = 1
    F = 2
    E = 3
    D = 4
    C = 5
    B = 6
    A = 7
    S = 8


@register_enum('Gallop::RaceDefine.Difficulty')
class RaceDifficulty(SafeIntEnum):
    Easy = 1
    Normal = 2
    Hard = 3
    VeryHard = 4
    Extreme = 5


@register_enum('Gallop::SingleModeDefine.CharaGradeType')
class CharaGradeType(SafeIntEnum):
    NONE = 0
    Debut = 1
    NoWin = 2
    Open = 3
    G3Silver = 4
    G3Gold = 5
    G2Silver = 6
    G2Gold = 7
    G1Bronze = 8
    G1Silver = 9
    G1Gold = 10
    Max = 10


@register_enum('Gallop::SingleModeDefine.State')
class SingleModeState(SafeIntEnum):
    Playing = 0
    NoWinEnd = 1
    TargetFailedEnd = 2
    TrueEnd = 3
    FinishComplete = 4


@register_enum('Gallop::SingleModeDefine.ScenarioId')
class SingleModeScenarioId(SafeIntEnum):
    """Career scenario IDs used to select scenario-specific response data."""

    URA = 1
    TeamRace = 2
    Live = 3
    Free = 4
    Venus = 5


@register_enum('Gallop::SingleModeDefine.PlayingState')
class SingleModePlayingState(SafeIntEnum):
    None_ = 0
    TurnStart = 1
    Race = 2
    RaceInGame = 3
    RaceResult = 4
    TurnEnd = 5
    MinigamePlaying = 6
    TeamRaceTop = 7
    TeamRacePlaying = 8
    TeamRaceResult = 9
    LiveTop = 10
    FactorSelect = 11
    VenusRaceTop = 12
    VenusRacePaddock = 13
    VenusRaceInGame = 14
    VenusRaceResult = 15
    FactorLotteryEnd = 20


@register_enum('Gallop::SingleModeLogInfoDefine.LogGroupType')
class SingleModeLogGroupType(SafeIntEnum):
    MainCharaEvent = 0
    SupportCharaEvent = 1
    MainScenarioEvent = 2
    TypicalCharaEvent = 3
    TypicalCharaNoIconEvent = 4
    TrainingEvent = 5
    RestEvent = 6
    OutingEvent = 7
    HealthRoomEvent = 8
    RaceEvent = 9
    ShopItemUseEvent = 10
    LiveSkillGet = 11
    VenusSpirit = 12
    LogGroupTypeMax = 13


@register_enum('Gallop::StoryLogInfo.InfoType')
class StoryLogInfoType(SafeIntEnum):
    Talk = 0
    Choice = 1
    System = 2


@register_enum('Gallop::StoryLogInfo.SoundType')
class StoryLogInfoSoundType(SafeIntEnum):
    VoiceStory = 0
    SeStoryRace = 1


@register_enum('Gallop::SingleModeDefine.EventContentsInfoType')
class SingleModeEventContentsInfoType(SafeIntEnum):
    None_ = 0
    TrainingChara = 1
    SupportCard = 2
    MainScenario = 3
    Dress = 4


@register_enum('Gallop::SingleModeEventPlayTiming')
class SingleModeEventPlayTiming(SafeIntEnum):
    None_ = 0
    TurnStart = 1
    RaceStart = 2
    RaceEnd = 3
    TurnEnd = 4
    ModeEnd = 5
    CommandStart = 6
    Continue = 7
    MiniGameEnd = 8
    TeamRaceEnd = 9
    TeamRaceAfterEvent = 10
    TeamRaceAfterTeamParameterRankUp = 11
    LiveEnd = 12
    GRSEnd = 13


@register_enum('Gallop::SingleModeDefine.CommandType')
class SingleModeCommandType(SafeIntEnum):
    None_ = 0
    Training = 1
    EatMeal = 2
    Outing = 3
    RaceEntry = 4
    Camp = 6
    Holiday = 7
    Hospital = 8
    Live = 10


@register_enum('Gallop::SingleModeDefine.ParameterType')
class SingleModeParameterType(SafeIntEnum):
    None_ = 0
    Speed = 1
    Stamina = 2
    Power = 3
    Guts = 4
    Wiz = 5
    Hp = 10
    Motivation = 20
    SkillPoint = 30


@register_enum('Gallop::MasterSingleModeLiveMasterBonus.SingleModeLiveMasterBonus.GainParameterTypeEnum')
class SingleModeLiveGainParameterType(SafeIntEnum):
    """API-facing parameter identifiers used by Grand Live master bonuses."""

    Speed = 1
    Stamina = 2
    Power = 3
    Guts = 4
    Wiz = 5
    SkillPt = 6


@register_enum('Gallop::WorkIdleSingleModeData.PlayingState')
class IdleSingleModePlayingState(SafeIntEnum):
    None_ = 0
    Playing = 1
    Finished = 2
    LogChecked = 3


@register_enum('Gallop::MainStoryDefine.RaceGimmickType')
class MainStoryRaceGimmickType(SafeIntEnum):
    NONE = 0
    Special_00 = 1
