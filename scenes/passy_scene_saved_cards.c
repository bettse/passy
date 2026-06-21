#include "../passy_i.h"
#include <storage/storage.h>
#include <dialogs/dialogs.h>

#define TAG "SceneSavedCards"

void passy_scene_saved_cards_on_enter(void* context) {
    Passy* passy = context;

    FuriString* path = furi_string_alloc();
    furi_string_printf(path, "/ext/apps_data/passy/dumps");

    Storage* storage = furi_record_open(RECORD_STORAGE);
    storage_common_mkdir(storage, furi_string_get_cstr(path));

    DialogsFileBrowserOptions browser_options;
    dialog_file_browser_set_basic_options(&browser_options, "*", NULL);
    browser_options.base_path = "/ext/apps_data/passy/dumps";
    browser_options.hide_dot_files = true;
    browser_options.hide_ext = false;

    FuriString* selected_path = furi_string_alloc();
    bool res = dialog_file_browser_show(
        passy->dialogs, passy->load_path, path, &browser_options);

    furi_record_close(RECORD_STORAGE);
    furi_string_free(path);
    furi_string_free(selected_path);

    if(res) {
        // passy->load_path now contains the path to the selected directory or file
        // If it's a directory (MRZ), we should go to ExploreCard scene!
        // The dialog_file_browser_show allows selecting directories? No, dialogs file browser mostly selects files.
        // Wait, if basic options set hide_dot_files, it lets you browse directories but only returns true if you select a FILE!
        // To select a directory, we need to use a custom submenu or build a simple list.
        scene_manager_next_scene(passy->scene_manager, PassySceneViewDG);
    } else {
        scene_manager_search_and_switch_to_previous_scene(
            passy->scene_manager, passy->is_pace_mode ? PassyScenePaceMenu : PassySceneMainMenu);
    }
}

bool passy_scene_saved_cards_on_event(void* context, SceneManagerEvent event) {
    UNUSED(context);
    UNUSED(event);
    return false;
}

void passy_scene_saved_cards_on_exit(void* context) {
    UNUSED(context);
}
