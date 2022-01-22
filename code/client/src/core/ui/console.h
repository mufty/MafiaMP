#pragma once

#include <utils/safe_win32.h>

#include "../../game/streaming/entity_factory.h"
#include "../../game/streaming/entity_tracking_info.h"

#include <integrations/client/instance.h>
#include <utils/states/machine.h>
#include <utils/states/state.h>

#include <memory>

namespace MafiaMP::Core::UI {
    class Console final {
      private:
        bool _shouldDisplayWidget = true;
        bool _autoScroll          = true;
        bool _isOpen              = false;
        std::vector<Game::Streaming::EntityTrackingInfo *> _TEMP_vehicles;
        std::shared_ptr<Framework::Utils::States::Machine> _machine;
        void Disconnect();
        void DespawnAll();
        void SpawnCar();
        void CrashMe();
        void BreakMe();
        void FormatLog(std::string log);

      public:
        Console(std::shared_ptr<Framework::Utils::States::Machine> machine): _machine(machine) {}
        ~Console() = default;

        void Toggle();
        bool Update();
        bool Open();
        bool Close();
    };
} // namespace MafiaMP::Core::UI
