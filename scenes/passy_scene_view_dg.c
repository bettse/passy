#include "../passy_i.h"
#include <storage/storage.h>
#define ASN_EMIT_DEBUG 0
#include <lib/asn1/DG1.h>

#define TAG "SceneViewDG"



void passy_scene_view_dg_on_enter(void* context) {
    Passy* passy = context;
    furi_string_reset(passy->text_box_store);
    FuriString* str = passy->text_box_store;
    
    // Read the selected file from passy->load_path into a BitBuffer
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* file = storage_file_alloc(storage);
    
    if(storage_file_open(file, furi_string_get_cstr(passy->load_path), FSAM_READ, FSOM_OPEN_EXISTING)) {
        size_t file_size = storage_file_size(file);
        uint8_t* buffer = malloc(file_size);
        if (buffer) {
            storage_file_read(file, buffer, file_size);
            
            // What file did we open?
            const char* path_cstr = furi_string_get_cstr(passy->load_path);
            if (strstr(path_cstr, "DG1.bin")) {
                DG1_t* dg1 = calloc(1, sizeof *dg1);
                asn_dec_rval_t rval = asn_decode(0, ATS_DER, &asn_DEF_DG1, (void**)&dg1, buffer, file_size);
                if(rval.code == RC_OK) {
                    uint8_t td_variant = 0;
                    if(dg1->mrz.size == 90) td_variant = 1;
                    else if(dg1->mrz.size == 88) td_variant = 3;
                    
                    char name[40] = {0};
                    uint8_t name_offset = td_variant == 3 ? 5 : 60;
                    uint8_t name_len = td_variant == 3 ? 39 : 30;
                    memcpy(name, dg1->mrz.buf + name_offset, name_len);
                    for(size_t i = sizeof(name) - 1; i > 0; i--) {
                        if(name[i] == '<') name[i] = '\0';
                        else break;
                    }
                    for(size_t i = 0; i < sizeof(name); i++) {
                        if(name[i] == '<') name[i] = ' ';
                    }
                    
                    if(td_variant == 3) { // Passport form factor
                        char* row_2 = (char*)dg1->mrz.buf + 44;
                        furi_string_cat_printf(str, "Name: %s\n", name);
                        furi_string_cat_printf(str, "Doc Number: %.9s\n", row_2);
                        furi_string_cat_printf(str, "DoB: %.6s\n", row_2 + 13);
                        furi_string_cat_printf(str, "Sex: %.1s\n", row_2 + 20);
                        furi_string_cat_printf(str, "Expiry: %.6s\n", row_2 + 21);
                    } else if(td_variant == 1) { // ID form factor
                        char* row_1 = (char*)dg1->mrz.buf + 0;
                        char* row_2 = (char*)dg1->mrz.buf + 30;
                        furi_string_cat_printf(str, "Name: %s\n", name);
                        furi_string_cat_printf(str, "Doc Number: %.9s\n", row_1 + 5);
                        furi_string_cat_printf(str, "DoB: %.6s\n", row_2);
                        furi_string_cat_printf(str, "Sex: %.1s\n", row_2 + 7);
                        furi_string_cat_printf(str, "Expiry: %.6s\n", row_2 + 8);
                    }
                } else {
                    furi_string_cat_printf(str, "Failed to decode DG1 ASN.1");
                }
                free(dg1);
            } else if (strstr(path_cstr, "DG2.bin")) {
                furi_string_cat_printf(str, "Facial Image Data\n\nSize: %zu bytes\n", file_size);
                furi_string_cat_printf(str, "Saved natively to SD card.\n");
                furi_string_cat_printf(str, "Use a PC to extract the JPEG or JPEG2000 image.");
            } else if (strstr(path_cstr, "DG7.bin")) {
                furi_string_cat_printf(str, "Signature Image Data\n\nSize: %zu bytes\n", file_size);
                furi_string_cat_printf(str, "Saved natively to SD card.");
            } else if (strstr(path_cstr, "EF_COM.bin")) {
                furi_string_cat_printf(str, "EF.COM Metadata\n\nSize: %zu bytes\n", file_size);
                furi_string_cat_printf(str, "Contains the index of all Data Groups present.");
            } else if (strstr(path_cstr, "EF_SOD.bin")) {
                furi_string_cat_printf(str, "Document Security Object\n\nSize: %zu bytes\n", file_size);
                furi_string_cat_printf(str, "Cryptographic signatures to verify document authenticity.");
            } else {
                furi_string_cat_printf(str, "Data Group %s\n\n", strrchr(path_cstr, '/') + 1);
                furi_string_cat_printf(str, "Size: %zu bytes\n", file_size);
                
                // Extremely simple ASCII extractor for DG11/DG12 to pull out readable text!
                furi_string_cat_printf(str, "\nStrings Found:\n");
                char current_string[128];
                int str_len = 0;
                for (size_t i = 0; i < file_size; i++) {
                    if (buffer[i] >= 0x20 && buffer[i] <= 0x7E) {
                        if (str_len < (int)sizeof(current_string) - 1) {
                            current_string[str_len++] = buffer[i];
                        }
                    } else {
                        if (str_len > 3) {
                            current_string[str_len] = '\0';
                            furi_string_cat_printf(str, "- %s\n", current_string);
                        }
                        str_len = 0;
                    }
                }
            }
            free(buffer);
        }
    } else {
        furi_string_cat_printf(str, "Failed to open file:\n%s", furi_string_get_cstr(passy->load_path));
    }
    
    storage_file_close(file);
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);

    text_box_set_text(passy->text_box, furi_string_get_cstr(passy->text_box_store));
    text_box_set_font(passy->text_box, TextBoxFontText);
    view_dispatcher_switch_to_view(passy->view_dispatcher, PassyViewTextBox);
}

bool passy_scene_view_dg_on_event(void* context, SceneManagerEvent event) {
    Passy* passy = context;
    bool consumed = false;
    
    if(event.type == SceneManagerEventTypeBack) {
        scene_manager_search_and_switch_to_previous_scene(
            passy->scene_manager, PassySceneSavedCards);
        consumed = true;
    }
    return consumed;
}

void passy_scene_view_dg_on_exit(void* context) {
    Passy* passy = context;
    text_box_reset(passy->text_box);
}
