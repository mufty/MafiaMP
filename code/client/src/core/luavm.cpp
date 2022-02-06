#include "luavm.h"
#include "../sdk/patterns.h"

#include <MinHook.h>
#include <logging/logger.h>
#include <utils/hooking/hooking.h>

#include <sstream>

#define LUA_MULTRET (-1)

using namespace SDK;

namespace MafiaMP::Core {
    using lua_State       = void;
    typedef int (*lua_CFunction)(lua_State *L);
    typedef struct luaL_Reg {
        const char *name;
        lua_CFunction func;
    } luaL_Reg;

    lua_State *g_luaState = nullptr;

    typedef int32_t(__cdecl *lua_pcall_t)(lua_State *L, int32_t nargs, int32_t nresults, int32_t errfunc);
    lua_pcall_t plua_pcall = nullptr;

    int32_t lua_pcall_(lua_State *L, int32_t nargs, int32_t nresults, int32_t errfunc) {
        return plua_pcall(L, nargs, nresults, errfunc);
    }

    typedef const char *(__cdecl *lua_tostring_t)(lua_State *L, int32_t idx);
    lua_tostring_t plua_tostring = nullptr;

    const char *lua_tostring_(lua_State *L, int32_t idx) {
        return plua_tostring(L, idx);
    }

    typedef uint32_t(__cdecl *lua_isstring_t)(lua_State *L, int32_t idx);
    lua_isstring_t plua_isstring = nullptr;

    __declspec(dllexport) uint32_t lua_isstring_(lua_State *L, int32_t idx) {
        return plua_isstring(L, idx);
    }

    typedef int32_t(__cdecl *luaL_loadbuffer_t)(lua_State *L, const char *buff, size_t size, const char *name);
    luaL_loadbuffer_t pluaL_loadbuffer = nullptr;

    extern "C" int luaopen_luammplib(lua_State *L);

    int32_t luaL_loadbuffer_(lua_State *L, const char *buff, size_t size, const char *name) {
        if (g_luaState == nullptr && L != nullptr) {
            Framework::Logging::GetLogger(LOG_LUA)->info("Lua wrapper is initialized.");
            g_luaState = L;
        }

        return pluaL_loadbuffer(L, "", 0, name);
    }

    int luaL_loadstring_mmp(lua_State *L, const char *s) {
        return pluaL_loadbuffer(L, s, strlen(s), s);
    }

    typedef lua_State *(__cdecl *lua_pushcclosure_t)(lua_State *L, lua_CFunction fn, int n, int64_t a);
    lua_pushcclosure_t plua_pushcclosure = nullptr;

    __declspec(dllexport) lua_State *lua_pushcclosure_(lua_State *L, lua_CFunction fn, int n, int64_t a = 0) {
        return plua_pushcclosure(L, fn, n, a);
    }

    typedef lua_State *(__cdecl *lua_setglobal_t)(lua_State *L, const char *var);
    lua_setglobal_t plua_setglobal = nullptr;

    __declspec(dllexport) lua_State *lua_setglobal_(lua_State *L, const char *var) {
        return plua_setglobal(L, var);
    }

#ifdef luaL_dostring
#undef luaL_dostring
#endif // luaL_dostring

#define luaL_dostring(L, s) (luaL_loadstring_mmp(L, s) || plua_pcall(L, 0, LUA_MULTRET, 0))

    static int32_t Lua_Log(lua_State *L) {
        // push the routine to reference and add a reference
        Framework::Logging::GetLogger(LOG_LUA)->debug(plua_tostring(L, 1));
        return 0;
    }

    static const struct luaL_Reg g_mafiaLib[] = {
        {"log", Lua_Log},
        {nullptr, nullptr}
    };

    static void SetupLuaAPIFunction(lua_State *state, const char *name, lua_CFunction func) {
        if (name == nullptr || func == nullptr)
            return;

        std::string functionName(name);
        Framework::Logging::GetLogger(LOG_LUA)->debug("Setting up function: " + functionName);
        plua_pushcclosure(state, func, 0, 0);
        plua_setglobal(state, name);
    }

    bool LuaVM::ExecuteString(const char *string) {
        if (g_luaState == nullptr || pluaL_loadbuffer == nullptr || plua_pcall == nullptr || plua_pushcclosure == nullptr || plua_setglobal == nullptr)
            return true;

        // TODO using luaL_setfuncs would be easier but don't know the stupid address
        auto *apiPtr = g_mafiaLib;
        auto *endApiPtr = g_mafiaLib + sizeof(g_mafiaLib) / sizeof(g_mafiaLib[0]);
        while (apiPtr < endApiPtr) { 
            SetupLuaAPIFunction(g_luaState, apiPtr->name, apiPtr->func);
            apiPtr++;
        }

        if (luaL_dostring(g_luaState, string)) {
            std::stringstream ss;
            ss << "Error loading Lua code into buffer:\n";
            ss << lua_tostring_(g_luaState, -1);
            Framework::Logging::GetLogger(LOG_LUA)->error(ss.str());
            error = ss.str();
            return false;
        }
        else if (lua_isstring_(g_luaState, -1)) {
            std::stringstream ss;
            ss << "Lua execute result:\n";
            ss << lua_tostring_(g_luaState, -1);
            Framework::Logging::GetLogger(LOG_LUA)->info(ss.str());
        }

        error = "";

        return true;
    }

    static InitFunction init([]() {
        MH_CreateHook(reinterpret_cast<void **>(gPatterns.Lua__pcallAddr), reinterpret_cast<void **>(lua_pcall_), reinterpret_cast<void **>(&plua_pcall));
        MH_CreateHook(reinterpret_cast<void **>(gPatterns.Lua__loadbufferAddr), reinterpret_cast<void **>(luaL_loadbuffer_), reinterpret_cast<void **>(&pluaL_loadbuffer));
        MH_CreateHook(reinterpret_cast<void **>(gPatterns.Lua__tostringAddr), reinterpret_cast<void **>(lua_tostring_), reinterpret_cast<void **>(&plua_tostring));
        MH_CreateHook(reinterpret_cast<void **>(gPatterns.Lua__isstringAddr), reinterpret_cast<void **>(lua_isstring_), reinterpret_cast<void **>(&plua_isstring));
        MH_CreateHook(reinterpret_cast<void **>(gPatterns.Lua__pushcclosureAddr), reinterpret_cast<void **>(lua_pushcclosure_), reinterpret_cast<void **>(&plua_pushcclosure));
        MH_CreateHook(reinterpret_cast<void **>(gPatterns.Lua__setglobalAddr), reinterpret_cast<void **>(lua_setglobal_), reinterpret_cast<void **>(&plua_setglobal));
    });
} // namespace MafiaMP::Core
