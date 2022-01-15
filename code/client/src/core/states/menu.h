#pragma once

#include <utils/states/state.h>

namespace MafiaMP::Core::States {
    class InMenuState: public Framework::Utils::States::IState {
      public:
        InMenuState();
        ~InMenuState();

        virtual const char *GetName() const override;
        virtual int32_t GetId() const override;

        virtual bool OnEnter(Framework::Utils::States::Machine *) override;
        virtual bool OnExit(Framework::Utils::States::Machine *) override;

        virtual bool OnUpdate(Framework::Utils::States::Machine *) override;

        private:
        void LockPlayerControls(bool);
    };
} // namespace MafiaMP::Core::States
