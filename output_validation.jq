# Public jq normalization contract for comparing live API responses with umadump exports.
# Each section identifies its API source, dump file, and entry-point filter pair.
# API entry points consume the full decoded response envelope, including .data;
# export entry points consume the emitted JSON. Unaltered exports use pass_through.
# Nested-section helpers are grouped before the entry points that consume them.
#
# Pair the same observation on both sides; retain object-key and meaningful array order.
# Example: jq -L . 'include "output_validation"; career_load_api' response.json

# Shared export entry point: retain every value, type, and key in the supplied dump.

def pass_through:
    .;

# ---------------------------------------------------------------------------
# Profile and collection exports
# ---------------------------------------------------------------------------

# API load/index -> support_card_data_api
# support_card_data.json -> support_card_data_export
def support_card_data_api:
    .data.support_card_list |
    map(
        # The client retains one timestamp; the export emits it under both API keys.
        .create_time = .possess_time |
        .viewer_id = 0
    );

def support_card_data_export:
    map(del(.extra_data));

# API load/index -> trained_chara_api; trained_chara/load -> trained_chara_refresh_api
# trained_chara_data.json -> trained_chara_export
# This helper consumes the API's veteran array, not a complete response envelope.
def normalize_trained_chara_array:
    map(
        (.single_mode_chara_id, .chara_seed,
         .succession_trained_chara_id_1, .succession_trained_chara_id_2,
         .route_id, .arrive_route_race_id, .race_cloth_id) = 0 |
        # Exclude the client's lazy win-count cache from parity on both sides.
        .wins = 0 |
        .race_result_list |= map(
            (.popularity, .result_time, .prize_money) = 0
        )
    );

def trained_chara_export:
    map(.wins = 0 | del(.icon_type, .memo));

def trained_chara_api:
    .data.trained_chara | normalize_trained_chara_array;

def trained_chara_refresh_api:
    .data.trained_chara_array | normalize_trained_chara_array;

# API load/index -> card_data_api; card_data.json -> pass_through
def card_data_api:
    .data.card_list;

# API friend/index -> friend_data_api; friend_data.json -> friend_data_export
# Only the two viewer-ID collections are canonicalized; other array order is retained.
def friend_data_api:
    .data |
    .user_info_summary_list |= (
        map(
            (.leader_chara_id, .leader_chara_dress_id, .partner_chara_id, .rank_score,
             .team_stadium_win_count, .single_mode_play_count, .team_evaluation_point) = 0 |
            .user_trained_chara |= (.trained_chara_id = 0) |
            .circle_user |= (
                .membership = 0 |
                (.join_time, .penalty_end_time, .item_request_end_time) = "0000-00-00 00:00:00" |
                .last_check_post_id = 0 |
                .ranking_result_check_time = "0000-00-00 00:00:00"
            )
        ) |
        sort_by(.viewer_id)
    ) |
    .follower_info_summary_list |= sort_by(.viewer_id) |
    .recommend_list |= map(
        (.follow_time, .follower_time) = "0000-00-00 00:00:00"
    );

def friend_data_export:
    .user_info_summary_list |= sort_by(.viewer_id) |
    .follower_info_summary_list |= sort_by(.viewer_id);

# API load/index -> honor_data_api; honor_data.json -> pass_through
def honor_data_api:
    .data.honor_info;

# API load/index -> trophy_load_index_api; trophy_data_limited.json -> pass_through
# Login records have no race IDs or win counts; build the documented limited shape.
def trophy_load_index_api:
    .data.login_trophy_info_array |
    map({
        "trophy_id": .trophy_id,
        "create_time": "0000-00-00 00:00:00",
        "race_instance_info_array": [
            {
                "race_instance_id": 0,
                "trophy_chara_info_array": (.chara_id_array | map({"chara_id": ., "win_count": 0}))
            }
        ]
    });

# API user/get_trophy_info -> trophy_refresh_api; trophy_data.json -> pass_through
def trophy_refresh_api:
    .data.user_trophy_info_array | map(.create_time = "0000-00-00 00:00:00");

# API load/index -> event_gallery_api; event_data.json -> event_gallery_export
# Timestamps/new flags are intentionally stubbed; gallery records are ordered by data ID.
def event_gallery_api:
    .data.event_data_array |
    map(.create_time = "0000-00-00 00:00:00" | .new_flag = 0) |
    sort_by(.data_id);

def event_gallery_export:
    .event_data_array | sort_by(.data_id);

# API load/index -> talk_gallery_api; talk_gallery_data.json -> pass_through
def talk_gallery_api:
    .data | {talk_gallery_list};

# ---------------------------------------------------------------------------
# Race and career exports
# ---------------------------------------------------------------------------

# API team_stadium/start -> team_stadium_replay_api
# race_replays/team_stadium/*.json -> pass_through
# Resource/reward sections and UI-only self evaluation are intentional placeholders.
def team_stadium_replay_api:
    .data |
    .rp_info = {} |
    (.item_info_array, .winning_reward_info_array) = [] |
    .race_start_params_array |= map(.self_evaluate = 0);

# Career helpers below consume a historical result, horse, common section, or Team
# dataset, respectively. career_load_api is the complete-response entry point.
# Horse history preserves the retained identity/conditions, but not these result details.
def career_historical_result_api:
    (.race_num, .popularity, .result_time, .bashin_diff, .bashin_diff_from_top,
     .skill_activate_count, .start_dash_state, .motivation, .is_excitement,
     .is_running_alone, .last_straight_line_rank, .auto_continue_num, .state) = 0;

def career_race_horse_api:
    .race_result_array |= map(career_historical_result_api);

# The client can retain old race context after clearing the current entry program.
def career_current_race_api:
    if .chara_info.race_program_id == 0 then
        (.race_start_info, .race_scenario, .race_reward_info, .add_trophy_info,
         .trophy_reward_info, .prev_chara_grade) = null
    else . end;

def career_common_api:
    # Account missions and campaign rewards are intentionally unreflected.
    (.race_add_reward_info, .mission_list, .story_event_mission_list, .story_event_chara_bonus_list) = [] |
    (.chara_info.support_card_array[] | select(.position == 6)) |= (.owner_viewer_id = 0) |
    .home_info.race_entry_restriction = 0 |
    career_current_race_api |
    (.race_start_info.race_horse_data[]?) |= career_race_horse_api;

def career_team_api:
    (.team_info | select(. != null)) |= (.team_rank_state = 0) |
    (.race_result_array[]?.race_horse_data_array[]) |= career_race_horse_api;

# API single_mode[/scenario]/load -> career_load_api
def career_load_api:
    .data |
    with_entries(select(.key == "single_mode_load_common" or (.key | endswith("_data_set")))) |
    .single_mode_load_common |= career_common_api |
    (.team_data_set | select(. != null)) |= career_team_api |
    # The client retains current win points, not the previous year's value.
    (.free_data_set | select(. != null)) |= (.prev_win_points = 0);

# ---------------------------------------------------------------------------
# Independent Training (Idle Mode) exports
# ---------------------------------------------------------------------------

# API idle_single_mode/status -> idle_status_api
# idle_single_mode/<identity>.json -> idle_status_export
def idle_status_api:
    .data.progress_info;

def idle_status_export:
    .progress_info;

# API idle_single_mode/end -> idle_end_api
# idle_single_mode/<identity>.json -> idle_end_export
def idle_end_projection:
    with_entries(select(.key == "progress_log_info" or .key == "end_info")) |
    .end_info |= (
        with_entries(select(.key == "chara_info" or .key == "reward_summary_info")) |
        .reward_summary_info |= with_entries(select(.key == "add_item_list"))
    );

def idle_end_api:
    .data | idle_end_projection;

def idle_end_export:
    idle_end_projection;
