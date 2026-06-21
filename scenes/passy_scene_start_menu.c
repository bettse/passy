#include "../passy_i.h"

enum SubmenuIndex {
    SubmenuIndexPace,
    SubmenuIndexBac,
};

void passy_scene_start_menu_submenu_callback(void* context, uint32_t index) {
    Passy* passy = context;
    view_dispatcher_send_custom_event(passy->view_dispatcher, index);
}

void passy_scene_start_menu_on_enter(void* context) {
    Passy* passy = context;
    Submenu* submenu = passy->submenu;

    submenu_add_item(
        submenu,
        "PACE (CAN)",
        SubmenuIndexPace,
        passy_scene_start_menu_submenu_callback,
        passy);
        
    submenu_add_item(
        submenu,
        "BAC (Original)",
        SubmenuIndexBac,
        passy_scene_start_menu_submenu_callback,
        passy);

    submenu_set_selected_item(
        submenu, scene_manager_get_scene_state(passy->scene_manager, PassySceneStartMenu));

    view_dispatcher_switch_to_view(passy->view_dispatcher, PassyViewMenu);
}

bool passy_scene_start_menu_on_event(void* context, SceneManagerEvent event) {
    Passy* passy = context;
    bool consumed = false;

    if(event.type == SceneManagerEventTypeCustom) {
        scene_manager_set_scene_state(passy->scene_manager, PassySceneStartMenu, event.event);
        if(event.event == SubmenuIndexPace) {
            passy->is_pace_mode = true;
            scene_manager_next_scene(passy->scene_manager, PassyScenePaceMenu);
            consumed = true;
        } else if(event.event == SubmenuIndexBac) {
            passy->is_pace_mode = false;
            scene_manager_next_scene(passy->scene_manager, PassySceneMainMenu);
            consumed = true;
        }
    }
    return consumed;
}

void passy_scene_start_menu_on_exit(void* context) {
    Passy* passy = context;
    submenu_reset(passy->submenu);
}
