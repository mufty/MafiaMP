#include <MinHook.h>
#include <utils/hooking/hook_function.h>
#include <utils/hooking/hooking.h>

#include "../../sdk/c_ie.h"
#include "../../sdk/entities/c_player_2.h"
#include "../../sdk/ue/game/humainai/c_character_controller.h"
#include "../../sdk/c_game.h"

#include "../../game/overrides/character_controller.h"
#include "../../game/overrides/scoped_entity_type_faker.h"

thread_local bool CreateNetCharacterController = false;

MafiaMP::Game::Overrides::CharacterController::OrigConstructor_t C_CharacterController__Constructor_Original = nullptr;
void *__fastcall C_CharacterController__Constructor(SDK::ue::game::humanai::C_CharacterController *pCharCtrler, SDK::C_Human2 *pHuman2) {
    if (CreateNetCharacterController) {
        SDK::C_IE::Free(pCharCtrler);
        return MafiaMP::Game::Overrides::CharacterController::Create(C_CharacterController__Constructor_Original, pHuman2);
    }
    else {
        return C_CharacterController__Constructor_Original(pCharCtrler, pHuman2);
    }
}

typedef void(__fastcall *C_CharacterController__Activate_t)(SDK::ue::game::humanai::C_CharacterController *, void *pBehaviorCharacter);
C_CharacterController__Activate_t C_CharacterController__Activate_Original = nullptr;
void __fastcall C_CharacterController__Activate(SDK::ue::game::humanai::C_CharacterController *pCharCtrler, void *pBehaviorCharacter) {
    if (MafiaMP::Game::Overrides::CharacterController::IsInstanceOfClass(pCharCtrler)) {
        MafiaMP::Game::Overrides::ScopedEntityTypeFaker faker(pCharCtrler->GetCharacter(), SDK::E_EntityType::E_ENTITY_PLAYER);
        C_CharacterController__Activate_Original(pCharCtrler, pBehaviorCharacter);

        uintptr_t pLocomotionCtrler = pCharCtrler->GetCharacterLocomotionController();
        if (pLocomotionCtrler) {
            *(uintptr_t *)(pLocomotionCtrler + 8) = *(uintptr_t *)(((uintptr_t)pCharCtrler) + 32);
        }
    }
    else {
        C_CharacterController__Activate_Original(pCharCtrler, pBehaviorCharacter);
    }
}

typedef void(__fastcall *C_CharacterController__ActivateAfterBehaviorCharacterActivation_t)(SDK::ue::game::humanai::C_CharacterController *);
C_CharacterController__ActivateAfterBehaviorCharacterActivation_t C_CharacterController__ActivateAfterBehaviorCharacterActivation_Original = nullptr;
void __fastcall C_CharacterController__ActivateAfterBehaviorCharacterActivation(SDK::ue::game::humanai::C_CharacterController *pCharCtrler) {
    if (MafiaMP::Game::Overrides::CharacterController::IsInstanceOfClass(pCharCtrler)) {
        MafiaMP::Game::Overrides::ScopedEntityTypeFaker faker(pCharCtrler->GetCharacter(), SDK::E_EntityType::E_ENTITY_PLAYER);
        C_CharacterController__ActivateAfterBehaviorCharacterActivation_Original(pCharCtrler);
    }
    else {
        C_CharacterController__ActivateAfterBehaviorCharacterActivation_Original(pCharCtrler);
    }
}

typedef void(__fastcall *C_CharacterController__Deactivate_t)(SDK::ue::game::humanai::C_CharacterController *);
C_CharacterController__Deactivate_t C_CharacterController__Deactivate_Original = nullptr;
void __fastcall C_CharacterController__Deactivate(SDK::ue::game::humanai::C_CharacterController *pCharCtrler) {
    if (MafiaMP::Game::Overrides::CharacterController::IsInstanceOfClass(pCharCtrler)) {
        MafiaMP::Game::Overrides::ScopedEntityTypeFaker faker(pCharCtrler->GetCharacter(), SDK::E_EntityType::E_ENTITY_HUMAN);
        C_CharacterController__Deactivate_Original(pCharCtrler);
    }
    else {
        C_CharacterController__Deactivate_Original(pCharCtrler);
    }
}

typedef void(__fastcall *C_CharacterController__ActivateHandler_t)(SDK::ue::game::humanai::C_CharacterController *, SDK::ue::game::humanai::C_CharacterStateHandler *, bool);
C_CharacterController__ActivateHandler_t C_CharacterController__ActivateHandler_Original = nullptr;
void __fastcall C_CharacterController__ActivateHandler(SDK::ue::game::humanai::C_CharacterController *pCharCtrler, SDK::ue::game::humanai::C_CharacterStateHandler *pStateHandler, bool a3) {
    if (MafiaMP::Game::Overrides::CharacterController::IsInstanceOfClass(pCharCtrler)) {
        if (SDK::ue::game::humanai::C_CharacterStateHandler::IsVehicleStateHandlerType(pStateHandler->GetStateHandlerType())) {
            MafiaMP::Game::Overrides::ScopedEntityTypeFaker faker(pCharCtrler->GetCharacter(), SDK::E_EntityType::E_ENTITY_HUMAN);
            ((MafiaMP::Game::Overrides::CharacterController *)pCharCtrler)->ActivateVehicleStateHandler(pStateHandler, a3);
        }
        else {
            MafiaMP::Game::Overrides::ScopedEntityTypeFaker faker(pCharCtrler->GetCharacter(), SDK::E_EntityType::E_ENTITY_PLAYER);
            C_CharacterController__ActivateHandler_Original(pCharCtrler, pStateHandler, a3);
        }
    }
    else {
        C_CharacterController__ActivateHandler_Original(pCharCtrler, pStateHandler, a3);
    }
}

typedef void(__fastcall *C_CharacterController__UpdateLocomotionHandlers_t)(SDK::ue::game::humanai::C_CharacterController *, float);
C_CharacterController__UpdateLocomotionHandlers_t C_CharacterController__UpdateLocomotionHandlers_Original = nullptr;
void __fastcall C_CharacterController__UpdateLocomotionHandlers(SDK::ue::game::humanai::C_CharacterController *pCharCtrler, float a2) {
    if (MafiaMP::Game::Overrides::CharacterController::IsInstanceOfClass(pCharCtrler)) {
        ((MafiaMP::Game::Overrides::CharacterController *)pCharCtrler)->OnUpdateLocomotionHandlers(a2);

        SDK::ue::game::humanai::C_CharacterStateHandler *pCurrentStateHandler = pCharCtrler->GetCurrentStateHandler();
        if (pCurrentStateHandler) {
            if (!SDK::ue::game::humanai::C_CharacterStateHandler::IsVehicleStateHandlerType(pCurrentStateHandler->GetStateHandlerType())) {
                MafiaMP::Game::Overrides::ScopedEntityTypeFaker faker(pCharCtrler->GetCharacter(), SDK::E_EntityType::E_ENTITY_PLAYER);
                pCurrentStateHandler->UpdateHumanFreq(a2);
            }
            else {
                pCurrentStateHandler->UpdateHumanFreq(a2);
            }
        }

        return;
    }

    C_CharacterController__UpdateLocomotionHandlers_Original(pCharCtrler, a2);
}

typedef void(__fastcall *C_CharacterController__UpdateAIFreq_t)(SDK::ue::game::humanai::C_CharacterController *, unsigned int);
C_CharacterController__UpdateAIFreq_t C_CharacterController__UpdateAIFreq_Original = nullptr;
void __fastcall C_CharacterController__UpdateAIFreq(SDK::ue::game::humanai::C_CharacterController *pCharCtrler, unsigned int a2) {
    if (MafiaMP::Game::Overrides::CharacterController::IsInstanceOfClass(pCharCtrler)) {
        MafiaMP::Game::Overrides::ScopedEntityTypeFaker faker(pCharCtrler->GetCharacter(), SDK::E_EntityType::E_ENTITY_PLAYER);
        C_CharacterController__UpdateAIFreq_Original(pCharCtrler, a2);
    }
    else {
        C_CharacterController__UpdateAIFreq_Original(pCharCtrler, a2);
    }
}

typedef void(__fastcall *C_CharacterController__ProcessAILocomotionRequest_t)(SDK::ue::game::humanai::C_CharacterController *, void *);
C_CharacterController__ProcessAILocomotionRequest_t C_CharacterController__ProcessAILocomotionRequest_Original = nullptr;
void __fastcall C_CharacterController__ProcessAILocomotionRequest(SDK::ue::game::humanai::C_CharacterController *pCharCtrler, void *a2) {
    if (MafiaMP::Game::Overrides::CharacterController::IsInstanceOfClass(pCharCtrler)) {
        return;
    }

    C_CharacterController__ProcessAILocomotionRequest_Original(pCharCtrler, a2);
}

typedef bool(__fastcall *C_Player2__IsInputDisabled_t)(SDK::C_Player2 *, int);
C_Player2__IsInputDisabled_t C_Player2__IsInputDisabled_Original = nullptr;
bool __fastcall C_Player2__IsInputDisabled(SDK::C_Player2 *pPlayer2, int DisabledInput) {
    return C_Player2__IsInputDisabled_Original(SDK::GetGame()->GetActivePlayer(), DisabledInput);
}

typedef void *(__fastcall *C_Player2__GetStamina_t)(SDK::C_Player2 *);
C_Player2__GetStamina_t C_Player2__GetStamina_Original = nullptr;
void *__fastcall C_Player2__GetStamina(SDK::C_Player2 *pPlayer2) {
    return C_Player2__GetStamina_Original(SDK::GetGame()->GetActivePlayer());
}

typedef bool(__fastcall *C_CharacterController__UpdateSprintMoveSpeed_t)(SDK::ue::game::humanai::C_CharacterController *, bool);
C_CharacterController__UpdateSprintMoveSpeed_t C_CharacterController__UpdateSprintMoveSpeed_Original = nullptr;
bool __fastcall C_CharacterController__UpdateSprintMoveSpeed(SDK::ue::game::humanai::C_CharacterController *pCharacterController, bool unk) {
    SDK::ue::game::humanai::C_CharacterController *pActivePlayerCharacterController = SDK::GetGame()->GetActivePlayer()->GetCharacterController();
    if (pActivePlayerCharacterController != pCharacterController) {
        pCharacterController->SetSprintMoveSpeed(pActivePlayerCharacterController->GetSprintMoveSpeed());
        return true;
    }
    else
        return C_CharacterController__UpdateSprintMoveSpeed_Original(pCharacterController, unk);
}

typedef bool(__fastcall *C_CharacterStateHandlerMove__IsSprinting_t)(SDK::ue::game::humanai::C_CharacterStateHandler *);
C_CharacterStateHandlerMove__IsSprinting_t C_CharacterStateHandlerMove__IsSprinting_Original = nullptr;
bool __fastcall C_CharacterStateHandlerMove__IsSprinting(SDK::ue::game::humanai::C_CharacterStateHandler *pMoveHandler) {
    SDK::C_Human2 *pCharacter = pMoveHandler->GetCharacter();
    if (SDK::GetGame()->GetActivePlayer() != pCharacter) {
        MafiaMP::Game::Overrides::ScopedEntityTypeFaker restore(pCharacter, SDK::E_EntityType::E_ENTITY_HUMAN);
        return C_CharacterStateHandlerMove__IsSprinting_Original(pMoveHandler);
    }
    else
        return C_CharacterStateHandlerMove__IsSprinting_Original(pMoveHandler);
}

typedef float(__fastcall *C_CharacterController__ConvertStickIntensity_t)(SDK::ue::game::humanai::C_CharacterController *, float, bool);
C_CharacterController__ConvertStickIntensity_t C_CharacterController__ConvertStickIntensity_Original = nullptr;
float __fastcall C_CharacterController__ConvertStickIntensity(SDK::ue::game::humanai::C_CharacterController *pController, float unk1, bool unk2) {
    SDK::C_Player2 *pActivePlayer = SDK::GetGame()->GetActivePlayer();
    if (pController->GetCharacter() != pActivePlayer)
        return C_CharacterController__ConvertStickIntensity_Original(pActivePlayer->GetCharacterController(), unk1, unk2);
    else
        return C_CharacterController__ConvertStickIntensity_Original(pController, unk1, unk2);
}

static InitFunction init([]() {
    const auto C_CharacterController__ConstructorAddr = hook::get_opcode_address("E8 ? ? ? ? EB 03 49 8B C7 48 89 87 ? ? ? ? 48 8B C7");
    MH_CreateHook((LPVOID)C_CharacterController__ConstructorAddr, (PBYTE)C_CharacterController__Constructor, reinterpret_cast<void **>(&C_CharacterController__Constructor_Original));

    const auto C_CharacterController__ActivateAddr = hook::get_opcode_address("E8 ? ? ? ? 48 8B 4B 08 48 8B 89 ? ? ? ?");
    MH_CreateHook((LPVOID)C_CharacterController__ActivateAddr, (PBYTE)C_CharacterController__Activate, reinterpret_cast<void **>(&C_CharacterController__Activate_Original));

    const auto C_CharacterController__ActivateAfterBehaviorCharacterActivationAddr = hook::get_opcode_address("E8 ? ? ? ? 4C 8B B7 ? ? ? ? 40 88 B7 ? ? ? ?");
    MH_CreateHook((LPVOID)C_CharacterController__ActivateAfterBehaviorCharacterActivationAddr, (PBYTE)C_CharacterController__ActivateAfterBehaviorCharacterActivation, reinterpret_cast<void **>(&C_CharacterController__ActivateAfterBehaviorCharacterActivation_Original));

    const auto C_CharacterController__DeactivateAddr = hook::get_opcode_address("E8 ? ? ? ? 4C 39 A6 ? ? ? ? 74 08");
    MH_CreateHook((LPVOID)C_CharacterController__DeactivateAddr, (PBYTE)C_CharacterController__Deactivate, reinterpret_cast<void **>(&C_CharacterController__Deactivate_Original));

    const auto C_CharacterController__ActivateHandlerAddr = hook::get_opcode_address("E8 ? ? ? ? 48 8D 56 74");
    MH_CreateHook((LPVOID)C_CharacterController__ActivateHandlerAddr, (PBYTE)C_CharacterController__ActivateHandler, reinterpret_cast<void **>(&C_CharacterController__ActivateHandler_Original));

    const auto C_CharacterController__UpdateLocomotionHandlersAddr = hook::get_opcode_address("E8 ? ? ? ? 48 8B 43 ? 80 78 ? ? 74 ? 48 8B BB ? ? ? ?");
    MH_CreateHook((LPVOID)C_CharacterController__UpdateLocomotionHandlersAddr, (PBYTE)C_CharacterController__UpdateLocomotionHandlers, reinterpret_cast<void **>(&C_CharacterController__UpdateLocomotionHandlers_Original));

    const auto C_CharacterController__UpdateAIFreqAddr = hook::get_opcode_address("E8 ? ? ? ? 48 8B 4B 30 32 D2");
    MH_CreateHook((LPVOID)C_CharacterController__UpdateAIFreqAddr, (PBYTE)C_CharacterController__UpdateAIFreq, reinterpret_cast<void **>(&C_CharacterController__UpdateAIFreq_Original));

    const auto C_CharacterController__ProcessAILocomotionRequestAddr = hook::get_opcode_address("E8 ? ? ? ? 49 8B 75 ? 41 83 CE ?");
    MH_CreateHook((LPVOID)C_CharacterController__ProcessAILocomotionRequestAddr, (PBYTE)C_CharacterController__ProcessAILocomotionRequest, reinterpret_cast<void **>(&C_CharacterController__ProcessAILocomotionRequest_Original));

    const auto C_Player2__IsInputDisabledAddr = hook::pattern("4C 63 C2 49 8D 40 66").get_first();
    MH_CreateHook((LPVOID)C_Player2__IsInputDisabledAddr, (PBYTE)C_Player2__IsInputDisabled, reinterpret_cast<void **>(&C_Player2__IsInputDisabled_Original));

    const auto C_Player2__GetStaminaAddr = hook::get_opcode_address("E8 ? ? ? ? 48 8B C8 44 8D 43 01");
    MH_CreateHook((LPVOID)C_Player2__GetStaminaAddr, (PBYTE)C_Player2__GetStamina, reinterpret_cast<void **>(&C_Player2__GetStamina_Original));

    const auto C_CharacterController__UpdateSprintMoveSpeedAddr = hook::get_opcode_address("E8 ? ? ? ? 0F B6 F8 84 C0 74 29");
    MH_CreateHook((LPVOID)C_CharacterController__UpdateSprintMoveSpeedAddr, (PBYTE)C_CharacterController__UpdateSprintMoveSpeed, reinterpret_cast<void **>(&C_CharacterController__UpdateSprintMoveSpeed_Original));

    const auto C_CharacterStateHandlerMove__IsSprintingAddr = hook::pattern("40 53 48 83 EC 20 48 8B C1 32 DB").get_first();
    MH_CreateHook((LPVOID)C_CharacterStateHandlerMove__IsSprintingAddr, (PBYTE)C_CharacterStateHandlerMove__IsSprinting, reinterpret_cast<void **>(&C_CharacterStateHandlerMove__IsSprinting_Original));

    const auto C_CharacterController__ConvertStickIntensityAddr = hook::get_opcode_address("E8 ? ? ? ? 48 8B 43 10 0F 28 D8");
    MH_CreateHook((LPVOID)C_CharacterController__ConvertStickIntensityAddr, (PBYTE)C_CharacterController__ConvertStickIntensity, reinterpret_cast<void **>(&C_CharacterController__ConvertStickIntensity_Original));
});
