#pragma once

#include "../../sdk/entities/c_entity.h"
#include "../../sdk/mafia/streaming/c_actors_slot_wrapper.h"
#include "../../sdk/ue/game/traffic/c_human_spawner.h"
#include "../../sdk/ue/sys/utils/c_hash_name.h"
#include "entity_type_factory.h"

#include <string>
#include <functional>

namespace MafiaMP::Game::Streaming {
    class EntityFactory {
      private:
        EntityTypeFactory<SDK::ue::sys::utils::C_HashName, SDK::ue::game::traffic::C_HumanSpawner> _humanFactory;
        EntityTypeFactory<std::string, SDK::mafia::streaming::C_ActorsSlotWrapper> _vehicleFactory;

      public:
        EntityFactory();

        EntityTrackingInfo *RequestHuman(SDK::ue::sys::utils::C_HashName);
        EntityTrackingInfo *RequestVehicle(const std::string &);

        void Update();

        void ReturnEntity(EntityTrackingInfo *);
        void ReturnAll();
    };
} // namespace MafiaMP::Game::Streaming
