#include "menu.h"
#include "states.h"

#include <utils/states/machine.h>

#include <imgui/imgui.h>
#include <imgui/backends/imgui_impl_win32.h>
#include <imgui/backends/imgui_impl_dx11.h>

#include "../../game/helpers/controls.h"

#include "../application.h"

namespace MafiaMP::Core::States {
    InMenuState::InMenuState() {}

    InMenuState::~InMenuState() {}

    int32_t InMenuState::GetId() const {
        return StateIds::Menu;
    }

    const char *InMenuState::GetName() const {
        return "InMenu";
    }

    bool InMenuState::OnEnter(Framework::Utils::States::Machine *) {
        // Set camera
        //TODO

        // Lock game controls
        Game::Helpers::Controls::Lock(true);

        // Enable cursor
        ImGuiIO &io = ImGui::GetIO();
        io.MouseDrawCursor = true;
        return true;
    }

    bool InMenuState::OnExit(Framework::Utils::States::Machine *) {
        // Hide cursor
        ImGuiIO &io        = ImGui::GetIO();
        io.MouseDrawCursor = false;
        return true;
    }

    bool InMenuState::OnUpdate(Framework::Utils::States::Machine *machine) {
        static bool shouldExit = false;
        gApplication->GetImGUI()->PushWidget([&]() {
            static bool open = true;
            if (!ImGui::Begin("Debug", &open)) {
                ImGui::End();
                return;
            }

            ImGui::Text("Have you heard about our lord and savior");
            static char serverIp[32] = "127.0.0.1";
            static char nickname[32] = "Player";
            ImGui::Text("Server IP: ");
            ImGui::SameLine();
            ImGui::InputText("##server_ip", serverIp, 32);
            ImGui::Text("Nickname: ");
            ImGui::SameLine();
            ImGui::InputText("##nickname", nickname, 32);
            if (ImGui::Button("Connect lol")) {
                // Update the application state for further usage
                MafiaMP::Core::CurrentState newApplicationState;
                newApplicationState._host = serverIp;
                newApplicationState._port = 1234;
                newApplicationState._nickname = nickname;
                MafiaMP::Core::gApplication->SetCurrentState(newApplicationState);

                // Request transition to next state (session connection)
                shouldExit = true;
                machine->RequestNextState(StateIds::SessionConnection);
            }

            ImGui::End();
        });
        return shouldExit;
    }
} // namespace MafiaMP::Core::States
