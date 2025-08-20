#include "../passy_i.h"

#define TAG "PassySceneAuthMenu"

enum SubmenuIndex {
    SubmenuIndexDocNr,
    SubmenuIndexDob,
    SubmenuIndexDoe,
    SubmenuIndexMethod,
    // SubmenuIndexSave,
    // SubmenuIndexLoad,
};

typedef enum {
    MrtdAuthMethodNone,
    MrtdAuthMethodAny,
    MrtdAuthMethodBac,
    MrtdAuthMethodPace,
    MRTD_AUTH_METHOD_COUNT,
} MrtdAuthMethod;

const char* mrtd_auth_method_string(MrtdAuthMethod method) {
    switch(method) {
    case MrtdAuthMethodBac:
        return "BAC";
    case MrtdAuthMethodPace:
        return "PACE";
    case MrtdAuthMethodNone:
        return "None";
    case MrtdAuthMethodAny:
        return "Any";
    default:
        return "Unknown";
    }
}

void passy_scene_auth_menu_auth_method_changed(VariableItem* item) {
    Passy* passy = variable_item_get_context(item);
    UNUSED(passy); // TODO: use to save selected method
    uint8_t index = variable_item_get_current_value_index(item);
    // TODO: store selected auth method in passy
    // nfc->dev->dev_data.mrtd_data.auth.method = index;
    variable_item_set_current_value_text(item, mrtd_auth_method_string(index));
}

void passy_scene_auth_menu_var_list_enter_callback(void* context, uint32_t index) {
    Passy* passy = context;
    view_dispatcher_send_custom_event(passy->view_dispatcher, index);
}

void passy_scene_auth_menu_on_enter(void* context) {
    Passy* passy = context;
    VariableItemList* variable_item_list = passy->variable_item_list;

    // By entering the Auth menu, we default to Auth: Any
    //TODO: read from passy, before: &mrtd_data->auth.method;
    MrtdAuthMethod temp_method = MrtdAuthMethodNone;
    MrtdAuthMethod* auth_method = &temp_method;
    if(*auth_method == MrtdAuthMethodNone) {
        *auth_method = MrtdAuthMethodAny;
    }

    VariableItem* item;
    uint8_t value_index;

    const size_t temp_str_size = 15;
    char temp_str[temp_str_size];

    item = variable_item_list_add(variable_item_list, "Document Nr.", 1, NULL, NULL);
    strlcpy(temp_str, passy->passport_number, temp_str_size);
    temp_str[temp_str_size - 1] = '\x00';
    if(strlen(temp_str) > 8) {
        temp_str[8] = '.';
        temp_str[9] = '.';
        temp_str[10] = '.';
        temp_str[11] = '\x00';
    }
    variable_item_set_current_value_text(item, temp_str);

    item = variable_item_list_add(variable_item_list, "Birth Date", 1, NULL, NULL);
    variable_item_set_current_value_text(item, passy->date_of_birth);

    item = variable_item_list_add(variable_item_list, "Expiry Date", 1, NULL, NULL);
    variable_item_set_current_value_text(item, passy->date_of_expiry);

    item = variable_item_list_add(
        variable_item_list,
        "Method",
        MRTD_AUTH_METHOD_COUNT,
        passy_scene_auth_menu_auth_method_changed,
        passy);

    value_index = *auth_method;
    variable_item_set_current_value_index(item, value_index);
    variable_item_set_current_value_text(item, mrtd_auth_method_string(value_index));

    //TODO: save/load
    //variable_item_list_add(variable_item_list, "Save parameters", 1, NULL, NULL);
    //variable_item_list_add(variable_item_list, "Load parameters", 1, NULL, NULL);

    variable_item_list_set_enter_callback(
        variable_item_list, passy_scene_auth_menu_var_list_enter_callback, passy);
    view_dispatcher_switch_to_view(passy->view_dispatcher, PassyViewVariableItemList);
}

bool passy_scene_auth_menu_on_event(void* context, SceneManagerEvent event) {
    Passy* passy = context;
    bool consumed = false;

    if(event.type == SceneManagerEventTypeCustom) {
        switch(event.event) {
        case SubmenuIndexDob:
            scene_manager_next_scene(passy->scene_manager, PassySceneDoBInput);
            consumed = true;
            break;
        case SubmenuIndexDoe:
            scene_manager_next_scene(passy->scene_manager, PassySceneDoEInput);
            consumed = true;
            break;
        case SubmenuIndexDocNr:
            scene_manager_next_scene(passy->scene_manager, PassyScenePassportNumberInput);
            consumed = true;
            break;
        case SubmenuIndexMethod:
            consumed = true;
            break;
            // case SubmenuIndexSave:
            //     scene_manager_next_scene(nfc->scene_manager, PassySceneAuthMenuSaveName);
            //     consumed = true;
            //     break;
            // case SubmenuIndexLoad:
            //     nfc_scene_passport_auth_load(nfc);
            //     consumed = true;
            //     break;
        }
    } else if(event.type == SceneManagerEventTypeBack) {
        consumed = scene_manager_previous_scene(passy->scene_manager);
    }
    return consumed;
}

void passy_scene_auth_menu_on_exit(void* context) {
    Passy* passy = context;

    // Clear view
    variable_item_list_reset(passy->variable_item_list);
}
