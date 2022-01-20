#pragma once

#include <utils/safe_win32.h>

#include "../game/streaming/entity_factory.h"
#include "../game/streaming/entity_tracking_info.h"

#include <integrations/client/instance.h>

#include <utils/states/machine.h>

namespace MafiaMP::Core {
    class Application: public Framework::Integrations::Client::Instance {
      private:
        Framework::Utils::States::Machine *_stateMachine;
        Game::Streaming::EntityFactory *_entityFactory;
        flecs::entity _localPlayer;

        std::vector<Game::Streaming::EntityTrackingInfo *> _TEMP_vehicles;

      public:
        virtual bool PostInit() override;
        virtual bool PreShutdown() override;
        virtual void PostUpdate() override;

        void InitNetworkingMessages();

        Framework::Utils::States::Machine* GetStateMachine() const {
            return _stateMachine;
        }

        Game::Streaming::EntityFactory *GetEntityFactory() const {
            return _entityFactory;
        }
    };

    extern std::unique_ptr<Application> gApplication;
} // namespace MafiaMP::Core
