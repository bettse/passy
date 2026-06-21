#include "../passy_i.h"
#include <dolphin/dolphin.h>

#define ASN_EMIT_DEBUG 0
#include <lib/asn1/DG1.h>

#define TAG "PassySceneReadCardSuccess"
// Thank you proxmark code for your passport parsing

static void
    passy_print_country_specific_info(FuriString* out, const char* issuer, const char* info) {
    furi_assert(issuer);
    furi_assert(info);
    furi_assert(out);

    if(strncmp(issuer, "GEO", 3) == 0) {
        furi_string_cat_printf(out, "Personal #: %.11s\n", info);
    }
}

void passy_scene_read_success_on_enter(void* context) {
    Passy* passy = context;

    dolphin_deed(DolphinDeedNfcReadSuccess);
    notification_message(passy->notifications, &sequence_success);

    furi_string_reset(passy->text_box_store);
    FuriString* str = passy->text_box_store;
    if(passy->read_type == PassyReadDG1) {
        DG1_t* dg1 = 0;
        dg1 = calloc(1, sizeof *dg1);
        assert(dg1);
        asn_dec_rval_t rval = asn_decode(
            0,
            ATS_DER,
            &asn_DEF_DG1,
            (void**)&dg1,
            bit_buffer_get_data(passy->DG1),
            bit_buffer_get_size_bytes(passy->DG1));

        if(rval.code == RC_OK) {
            FURI_LOG_I(TAG, "ASN.1 decode success");

            char payloadDebug[384] = {0};
            memset(payloadDebug, 0, sizeof(payloadDebug));
            (&asn_DEF_DG1)
                ->op->print_struct(
                    &asn_DEF_DG1, dg1, 1, passy_print_struct_callback, payloadDebug);
            if(strlen(payloadDebug) > 0) {
                FURI_LOG_D(TAG, "DG1: %s", payloadDebug);
            } else {
                FURI_LOG_D(TAG, "Received empty Payload");
            }

            const char* document_code = (const char*)dg1->mrz.buf;

            if(strncmp(document_code, "IP", 2) == 0) {
                furi_string_cat_printf(str, "Passport card (IP)\n");
            } else if(document_code[0] == 'I') {
                furi_string_cat_printf(str, "ID Card (I)\n");
            } else if(document_code[0] == 'P') {
                furi_string_cat_printf(str, "Passport book (P)\n");
            } else if(document_code[0] == 'A') {
                furi_string_cat_printf(str, "Residency Permit (A)\n");
            } else if(strncmp(document_code, "TR", 2) == 0) {
                furi_string_cat_printf(str, "Residency Permit (TR)\n");
            } else {
                furi_string_cat_printf(
                    str, "Unknown (%c%c)\n", document_code[0], document_code[1]);
            }

            uint8_t td_variant = 0;
            if(dg1->mrz.size == 90) {
                td_variant = 1;
            } else if(dg1->mrz.size == 88) {
                td_variant = 3;
            } else {
                FURI_LOG_W(TAG, "MRZ length (%zu) is unexpected.", dg1->mrz.size);
            }

            char name[40] = {0};
            memset(name, 0, sizeof(name));
            uint8_t name_offset = td_variant == 3 ? 5 : 60;
            uint8_t name_len = td_variant == 3 ? 39 : 30;
            memcpy(name, dg1->mrz.buf + name_offset, name_len);
            // Work backwards replace < at the end with \0
            for(size_t i = sizeof(name) - 1; i > 0; i--) {
                if(name[i] == '<') {
                    name[i] = '\0';
                } else {
                    break;
                }
            }
            // Work forwards replace < with space
            for(size_t i = 0; i < sizeof(name); i++) {
                if(name[i] == '<') {
                    name[i] = ' ';
                }
            }

            if(td_variant == 3) { // Passport form factor
                char* row_1 = (char*)dg1->mrz.buf + 0;
                char* row_2 = (char*)dg1->mrz.buf + 44;

                furi_string_cat_printf(str, "Issuing state: %.3s\n", row_1 + 2);
                furi_string_cat_printf(str, "Nationality: %.3s\n", row_2 + 10);
                furi_string_cat_printf(str, "Name: %s\n", name);
                furi_string_cat_printf(str, "Doc Number: %.9s\n", row_2);
                furi_string_cat_printf(str, "DoB: %.6s\n", row_2 + 13);
                furi_string_cat_printf(str, "Sex: %.1s\n", row_2 + 20);
                furi_string_cat_printf(str, "Expiry: %.6s\n", row_2 + 21);

                furi_string_cat_printf(str, "\n");
                furi_string_cat_printf(str, "Raw data:\n");
                furi_string_cat_printf(str, "%.44s\n", row_1);
                furi_string_cat_printf(str, "%.44s\n", row_2);
            } else if(td_variant == 1) { // ID form factor
                char* row_1 = (char*)dg1->mrz.buf + 0;
                char* row_2 = (char*)dg1->mrz.buf + 30;
                char* row_3 = (char*)dg1->mrz.buf + 60;

                const char* issuing_state = row_1 + 2;

                furi_string_cat_printf(str, "Issuing state: %.3s\n", issuing_state);
                furi_string_cat_printf(str, "Nationality: %.3s\n", row_2 + 15);
                furi_string_cat_printf(str, "Name: %s\n", name);
                furi_string_cat_printf(str, "Doc Number: %.9s\n", row_1 + 5);
                furi_string_cat_printf(str, "DoB: %.6s\n", row_2);
                furi_string_cat_printf(str, "Sex: %.1s\n", row_2 + 7);
                furi_string_cat_printf(str, "Expiry: %.6s\n", row_2 + 8);
                passy_print_country_specific_info(str, issuing_state, row_1 + 15);

                furi_string_cat_printf(str, "\n");
                furi_string_cat_printf(str, "Raw data:\n");
                furi_string_cat_printf(str, "%.30s\n", row_1);
                furi_string_cat_printf(str, "%.30s\n", row_2);
                furi_string_cat_printf(str, "%.30s\n", row_3);
            }

        } else {
            FURI_LOG_E(TAG, "ASN.1 decode failed: %d.  %d consumed", rval.code, rval.consumed);
            furi_string_cat_printf(str, "%s\n", bit_buffer_get_data(passy->DG1));
        }

        free(dg1);
        dg1 = 0;

    } else if(passy->read_type == PassyReadDG2 || passy->read_type == PassyReadDG7) {
        const char* dg_type = passy->read_type == PassyReadDG2 ? "DG2" : "DG7";
        furi_string_cat_printf(
            str, "Saved to dumps/%s/%s.*\n", passy->passport_number, dg_type);
    } else if(passy->read_type == PassyReadDumpAll) {
        furi_string_cat_printf(
            str, "Successfully dumped all files\nto dumps/%s/\n", passy->passport_number);
    } else {
        const char* file_name;
        if (passy->read_type == PassyReadCOM) file_name = "EF_COM.bin";
        else if (passy->read_type == PassyReadSOD) file_name = "EF_SOD.bin";
        else {
            static char buf[16];
            snprintf(buf, sizeof(buf), "DG%d.bin", passy->read_type & 0xFF);
            file_name = buf;
        }

        furi_string_cat_printf(
            str, "Saved to dumps/%s/%s\n\nStrings found:\n", passy->passport_number, file_name);

        FuriString* path = furi_string_alloc_printf(
            "/ext/apps_data/passy/dumps/%s/%s", passy->passport_number, file_name);
        passy_furi_string_filename_safe(path);

        Storage* storage = furi_record_open(RECORD_STORAGE);
        File* file = storage_file_alloc(storage);
        if(storage_file_open(file, furi_string_get_cstr(path), FSAM_READ, FSOM_OPEN_EXISTING)) {
            size_t file_size = storage_file_size(file);
            uint8_t* buffer = malloc(file_size);
            if (buffer) {
                storage_file_read(file, buffer, file_size);
                
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
                free(buffer);
            }
        }
        storage_file_close(file);
        storage_file_free(file);
        furi_record_close(RECORD_STORAGE);
        furi_string_free(path);
    }
    text_box_set_font(passy->text_box, TextBoxFontText);
    text_box_set_text(passy->text_box, furi_string_get_cstr(passy->text_box_store));
    view_dispatcher_switch_to_view(passy->view_dispatcher, PassyViewTextBox);
}

bool passy_scene_read_success_on_event(void* context, SceneManagerEvent event) {
    Passy* passy = context;
    bool consumed = false;

    if(event.type == SceneManagerEventTypeCustom) {
    } else if(event.type == SceneManagerEventTypeBack) {
        const uint32_t possible_scenes[] = {PassySceneAdvancedMenu, PassySceneMainMenu, PassyScenePaceMenu};
        scene_manager_search_and_switch_to_previous_scene_one_of(
            passy->scene_manager, possible_scenes, COUNT_OF(possible_scenes));
        consumed = true;
    }
    return consumed;
}

void passy_scene_read_success_on_exit(void* context) {
    Passy* passy = context;

    // Clear view
    text_box_reset(passy->text_box);
}
