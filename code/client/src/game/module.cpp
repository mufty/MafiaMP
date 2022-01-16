#include "module.h"

#include "../core/application.h"
#include "../sdk/c_game.h"
#include "../sdk/entities/c_car.h"
#include "../sdk/entities/c_player_2.h"
#include "../sdk/entities/c_vehicle.h"
#include "../sdk/entities/human/c_human_weapon_controller.h"

#include <SDL.h>
#include <logging/logger.h>
#include <utils/hooking/hooking.h>

#include <MinHook.h>



namespace MafiaMP::Game {
    Globals gGlobals;

    ModModule::ModModule() {
        StaticRegister(this);
    }

    void ModModule::OnSysInit(SDK::I_TickedModuleCallEventContext &) {
        // Create our core module application
        Core::gApplication.reset(new Core::Application);

        // Init our main application
        if (Core::gApplication && !Core::gApplication->IsInitialized()) {
            Framework::Graphics::RendererConfiguration rendererOptions = {};
            rendererOptions.backend = Framework::Graphics::RendererBackend::BACKEND_D3D_11;

            Framework::Integrations::Client::InstanceOptions opts;
            opts.discordAppId    = 763114144454672444;
            opts.useRenderer     = true;
            opts.usePresence     = true;
            opts.rendererOptions = rendererOptions;

            Core::gApplication->Init(opts);

            // Next steps requires an initialized application
            if (!Core::gApplication->IsInitialized()) {
                return;
            }

            // Init the render device
            MafiaMP::Core::gApplication->GetRenderer()->SetWindow(gGlobals.Window);
            MafiaMP::Core::gApplication->GetRenderer()->GetD3D11Backend()->Init(gGlobals.RenderDevice->_device, gGlobals.RenderDevice->_context);
            Framework::Logging::GetLogger(FRAMEWORK_INNER_GRAPHICS)->info("[RenderDevice] Initialized (device {:p}, context {:p} and swapchain {:p})", fmt::ptr(gGlobals.RenderDevice->_device), fmt::ptr(gGlobals.RenderDevice->_context), fmt::ptr(gGlobals.SwapChain));

            // Init the ImGui internal instance
            Framework::External::ImGUI::Config imguiConfig;
            imguiConfig.renderBackend = Framework::External::ImGUI::RenderBackend::D3D11;
            imguiConfig.windowBackend = Framework::External::ImGUI::WindowBackend::WIN_32;
            imguiConfig.renderer      = MafiaMP::Core::gApplication->GetRenderer();
            imguiConfig.windowHandle  = gGlobals.Window;
            if (MafiaMP::Core::gApplication->GetImGUI()->Init(imguiConfig) != Framework::External::ImGUI::Error::IMGUI_NONE) {
                Framework::Logging::GetLogger(FRAMEWORK_INNER_GRAPHICS)->info("ImGUI has failed to init");
            }
        }
    }

    void ModModule::OnGameRender(SDK::I_TickedModuleCallEventContext &) {
        const auto app = MafiaMP::Core::gApplication.get();

        if (!app || (app && !app->IsInitialized()))
            return;

        // Tick our rendering thread
        app->Render();
    }

    void ModModule::OnSysShutdown(SDK::I_TickedModuleCallEventContext &) {
        // Properly shutdown our main application
        if (Core::gApplication && Core::gApplication->IsInitialized()) {
            Core::gApplication->Shutdown();
        }
        delete this;
    }

    static Game::Streaming::EntityTrackingInfo *info = nullptr;
    static SDK::C_Car *m_pCar                        = nullptr;
    void ModModule::OnGameTick(SDK::I_TickedModuleCallEventContext &) {
        if (!Core::gApplication || !Core::gApplication->IsInitialized()) {
            return;
        }

        Core::gApplication->Update();

        // Tick discord instance - Temporary
        const auto discordApi = Core::gApplication->GetPresence();
        if (discordApi && discordApi->IsInitialized()) {
            discordApi->SetPresence("Freeroam", "Screwing around", discord::ActivityType::Playing);
        }

#if 1
        if (GetAsyncKeyState(VK_F3) & 0x1) {
            Core::gApplication->GetEntityFactory()->ReturnAll();
        }

        if (GetAsyncKeyState(VK_F1) & 0x1) {
            printf("asking car\n");
            info = Core::gApplication->GetEntityFactory()->RequestVehicle("berkley_810");

            const auto OnCarRequestFinish = [&](bool success) {
                if (success) {
                    m_pCar = reinterpret_cast<SDK::C_Car *>(info->GetEntity());
                    if (!m_pCar) {
                        return;
                    }
                    m_pCar->GameInit();
                    m_pCar->Activate();
                    m_pCar->Unlock();

                    auto localPlayer = SDK::GetGame()->GetActivePlayer();

                    SDK::ue::sys::math::C_Vector newPos = localPlayer->GetPos();
                    SDK::ue::sys::math::C_Quat newRot   = localPlayer->GetRot();
                    SDK::ue::sys::math::C_Matrix transform = {};
                    transform.Identity();
                    transform.SetRot(newRot);
                    transform.SetPos(newPos);
                    m_pCar->GetVehicle()->SetVehicleMatrix(transform, SDK::ue::sys::core::E_TransformChangeType::DEFAULT);
                }
                else {
                    info = nullptr;
                }
            };

            const auto OnCarReturned = [&](bool wasCreated) {
                if (wasCreated && m_pCar) {
                    m_pCar->Deactivate();
                    m_pCar->GameDone();
                    m_pCar->Release();
                }

                m_pCar = nullptr;
                info   = nullptr;
            };

            info->SetRequestFinishCallback(OnCarRequestFinish);
            info->SetReturnCallback(OnCarReturned);
        }
#endif
    }

    void ModModule::StaticRegister(ModModule *instance) {
        auto *mgr = SDK::GetTickedModuleManager();
        if (!mgr) {
            Framework::Logging::GetLogger("ModModule")->error("Failed to acquire C_TickedModuleManager instance");
            return;
        }

        mgr->AddAction(SDK::E_TmEvent::E_TMEVENT_SYSTEM_INIT, 9999, instance, (SDK::TickedModuleCallback)(&ModModule::OnSysInit), -1.0f, 0, 0, "[TM]ModModule::OnSysInit");
        mgr->EnableAction(SDK::E_TmEvent::E_TMEVENT_GAME_PAUSED, instance, (SDK::TickedModuleCallback)(&ModModule::OnSysInit), true);

        mgr->AddAction(SDK::E_TmEvent::E_TMEVENT_SYSTEM_DONE, 500, instance, (SDK::TickedModuleCallback)(&ModModule::OnSysShutdown), -1.0f, 0, 0, "[TM]ModModule::OnSysShutdown");
        mgr->EnableAction(SDK::E_TmEvent::E_TMEVENT_SYSTEM_DONE, instance, (SDK::TickedModuleCallback)(&ModModule::OnSysShutdown), true);

        mgr->AddAction(SDK::E_TmEvent::E_TMEVENT_RENDER, 99999, instance, (SDK::TickedModuleCallback)(&ModModule::OnGameRender), -1.0f, 0, 0, "[TM]ModModule::OnGameRender");
        mgr->EnableAction(SDK::E_TmEvent::E_TMEVENT_RENDER, instance, (SDK::TickedModuleCallback)(&ModModule::OnGameRender), true);

        mgr->AddAction(SDK::E_TmEvent::E_TMEVENT_TICK, 400, instance, (SDK::TickedModuleCallback)(&ModModule::OnGameTick), -1.0f, 0, 0, "[TM]ModModule::OnGameTick");
        mgr->EnableAction(SDK::E_TmEvent::E_TMEVENT_TICK, instance, (SDK::TickedModuleCallback)(&ModModule::OnGameTick), true);

        Framework::Logging::GetLogger("ModModule")->info("Registration success");
    }

    void ModModule::StaticHandleShutdown(ModModule *) {
        Framework::Logging::GetLogger("ModModule")->info("Shutdown success");
        // TODO: find a way to properly shutdown the game
    }
} // namespace MafiaMP::Game
