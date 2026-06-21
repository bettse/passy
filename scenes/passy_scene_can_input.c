#include "../passy_i.h"

void passy_scene_can_input_callback(void* context) {
    Passy* passy = context;
    view_dispatcher_send_custom_event(passy->view_dispatcher, PassyCustomEventTextInputDone);
}

void passy_scene_can_input_on_enter(void* context) {
    Passy* passy = context;

    text_input_reset(passy->text_input);
    text_input_set_header_text(passy->text_input, "Enter CAN (6 digits)");

    text_input_set_result_callback(
        passy->text_input,
        passy_scene_can_input_callback,
        passy,
        passy->text_store,
        PASSY_PASSPORT_NUMBER_MAX_LENGTH,
        true);

    view_dispatcher_switch_to_view(passy->view_dispatcher, PassyViewTextInput);
}

bool passy_scene_can_input_on_event(void* context, SceneManagerEvent event) {
    Passy* passy = context;
    bool consumed = false;

    if(event.type == SceneManagerEventTypeCustom) {
        if(event.event == PassyCustomEventTextInputDone) {
            strlcpy(passy->passport_number, passy->text_store, sizeof(passy->passport_number));
            passy_save_can_info(passy);
            // In PACE CAN mode, DoB and DoE are not needed, skip directly to Read
            memset(passy->date_of_birth, 0, sizeof(passy->date_of_birth));
            memset(passy->date_of_expiry, 0, sizeof(passy->date_of_expiry));
            
            scene_manager_search_and_switch_to_previous_scene(
                passy->scene_manager, PassyScenePaceMenu);
            consumed = true;
        }
    }
    return consumed;
}

void passy_scene_can_input_on_exit(void* context) {
    UNUSED(context);
}
