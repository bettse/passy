#include "../passy_i.h"

enum SubmenuIndex {
    SubmenuIndexReadDG3,
    SubmenuIndexReadDG4,
    SubmenuIndexReadDG5,
    SubmenuIndexReadDG7,
    SubmenuIndexReadDG11,
    SubmenuIndexReadDG12,
    SubmenuIndexReadDG13,
    SubmenuIndexReadDG14,
    SubmenuIndexReadDG15,
    SubmenuIndexReadCOM,
    SubmenuIndexReadSOD,
};

void passy_scene_more_menu_submenu_callback(void* context, uint32_t index) {
    Passy* passy = context;
    view_dispatcher_send_custom_event(passy->view_dispatcher, index);
}

void passy_scene_more_menu_on_enter(void* context) {
    Passy* passy = context;
    Submenu* submenu = passy->submenu;
    submenu_reset(submenu);

    submenu_add_item(submenu, "DG3 (Fingerprints)", SubmenuIndexReadDG3, passy_scene_more_menu_submenu_callback, passy);
    submenu_add_item(submenu, "DG4 (Iris)", SubmenuIndexReadDG4, passy_scene_more_menu_submenu_callback, passy);
    submenu_add_item(submenu, "DG5 (Portrait)", SubmenuIndexReadDG5, passy_scene_more_menu_submenu_callback, passy);
    submenu_add_item(submenu, "DG7 (Signature)", SubmenuIndexReadDG7, passy_scene_more_menu_submenu_callback, passy);
    submenu_add_item(submenu, "DG11 (Addt. Details)", SubmenuIndexReadDG11, passy_scene_more_menu_submenu_callback, passy);
    submenu_add_item(submenu, "DG12 (Doc Details)", SubmenuIndexReadDG12, passy_scene_more_menu_submenu_callback, passy);
    submenu_add_item(submenu, "DG13 (Optional Details)", SubmenuIndexReadDG13, passy_scene_more_menu_submenu_callback, passy);
    submenu_add_item(submenu, "DG14 (Security Options)", SubmenuIndexReadDG14, passy_scene_more_menu_submenu_callback, passy);
    submenu_add_item(submenu, "DG15 (Active Auth Key)", SubmenuIndexReadDG15, passy_scene_more_menu_submenu_callback, passy);
    submenu_add_item(submenu, "EF.COM (DG Index)", SubmenuIndexReadCOM, passy_scene_more_menu_submenu_callback, passy);
    submenu_add_item(submenu, "EF.SOD (Security Object)", SubmenuIndexReadSOD, passy_scene_more_menu_submenu_callback, passy);

    submenu_set_selected_item(
        submenu, scene_manager_get_scene_state(passy->scene_manager, PassySceneMoreMenu));
    view_dispatcher_switch_to_view(passy->view_dispatcher, PassyViewMenu);
}

bool passy_scene_more_menu_on_event(void* context, SceneManagerEvent event) {
    Passy* passy = context;
    bool consumed = false;

    if(event.type == SceneManagerEventTypeCustom) {
        scene_manager_set_scene_state(passy->scene_manager, PassySceneMoreMenu, event.event);
        
        if(event.event == SubmenuIndexReadDG3) {
            passy->read_type = PassyReadDG3;
            scene_manager_next_scene(passy->scene_manager, PassySceneAdvWarning);
        } else if(event.event == SubmenuIndexReadDG4) {
            passy->read_type = PassyReadDG4;
            scene_manager_next_scene(passy->scene_manager, PassySceneAdvWarning);
        } else {
            // Assign PassyReadType based on index
            if(event.event == SubmenuIndexReadDG5) passy->read_type = PassyReadDG5;
            else if(event.event == SubmenuIndexReadDG7) passy->read_type = PassyReadDG7;
            else if(event.event == SubmenuIndexReadDG11) passy->read_type = PassyReadDG11;
            else if(event.event == SubmenuIndexReadDG12) passy->read_type = PassyReadDG12;
            else if(event.event == SubmenuIndexReadDG13) passy->read_type = PassyReadDG13;
            else if(event.event == SubmenuIndexReadDG14) passy->read_type = PassyReadDG14;
            else if(event.event == SubmenuIndexReadDG15) passy->read_type = PassyReadDG15;
            else if(event.event == SubmenuIndexReadCOM) passy->read_type = PassyReadCOM;
            else if(event.event == SubmenuIndexReadSOD) passy->read_type = PassyReadSOD;
            
            scene_manager_next_scene(passy->scene_manager, PassySceneRead);
        }
        consumed = true;
    } else if(event.type == SceneManagerEventTypeBack) {
        consumed = scene_manager_search_and_switch_to_previous_scene(
            passy->scene_manager, passy->is_pace_mode ? PassyScenePaceMenu : PassySceneMainMenu);
    }
    return consumed;
}

void passy_scene_more_menu_on_exit(void* context) {
    Passy* passy = context;
    submenu_reset(passy->submenu);
}
