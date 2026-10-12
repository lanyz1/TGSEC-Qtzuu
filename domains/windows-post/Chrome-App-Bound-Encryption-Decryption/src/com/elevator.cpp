// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "elevator.hpp"
#include <stdexcept>
#include <sstream>

namespace Com
{

    Elevator::Elevator()
    {
        HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
        if (FAILED(hr))
            throw std::runtime_error("CoInitializeEx failed");
        m_initialized = true;
    }

    Elevator::~Elevator()
    {
        if (m_initialized)
            CoUninitialize();
    }

    std::vector<uint8_t> Elevator::DecryptKey(
        const std::vector<uint8_t> &encryptedKey,
        const CLSID &clsid,
        const IID &iid,
        const std::optional<IID> &iid_v2,
        bool isEdge,
        bool isAvast)
    {
        BSTR bstrEnc = SysAllocStringByteLen(reinterpret_cast<const char *>(encryptedKey.data()), (UINT)encryptedKey.size());
        if (!bstrEnc)
            throw std::runtime_error("SysAllocStringByteLen failed");

        struct BstrDeleter
        {
            void operator()(BSTR b) { SysFreeString(b); }
        };
        std::unique_ptr<OLECHAR[], BstrDeleter> encGuard(bstrEnc);

        BSTR bstrPlain = nullptr;
        DWORD comErr = 0;
        HRESULT hr = E_FAIL;

        if (isEdge)
        {
            // Edge uses a different interface chain with IElevatorEdgeBase
            if (iid_v2.has_value())
            {
                Microsoft::WRL::ComPtr<IEdgeElevator2Final> elevator2;
                hr = CoCreateInstance(clsid, nullptr, CLSCTX_LOCAL_SERVER, iid_v2.value(), &elevator2);
                if (SUCCEEDED(hr))
                {
                    CoSetProxyBlanket(elevator2.Get(), RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL,
                                      RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_DYNAMIC_CLOAKING);
                    hr = elevator2->DecryptData(bstrEnc, &bstrPlain, &comErr);
                }
            }

            if (!iid_v2.has_value() || hr == E_NOINTERFACE || FAILED(hr))
            {
                Microsoft::WRL::ComPtr<IEdgeElevatorFinal> elevator;
                hr = CoCreateInstance(clsid, nullptr, CLSCTX_LOCAL_SERVER, iid, &elevator);
                if (SUCCEEDED(hr))
                {
                    CoSetProxyBlanket(elevator.Get(), RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL,
                                      RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_DYNAMIC_CLOAKING);
                    hr = elevator->DecryptData(bstrEnc, &bstrPlain, &comErr);
                }
            }
        }
        else if (isAvast)
        {
            // Avast uses same IID as Chrome base IElevator but has 12 methods instead of 3
            // DecryptData is at vtable slot 13 (offset 104) instead of slot 5 (offset 40)
            Microsoft::WRL::ComPtr<IAvastElevator> elevator;
            hr = CoCreateInstance(clsid, nullptr, CLSCTX_LOCAL_SERVER, iid, &elevator);
            if (SUCCEEDED(hr))
            {
                CoSetProxyBlanket(elevator.Get(), RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL,
                                  RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_DYNAMIC_CLOAKING);
                hr = elevator->DecryptData(bstrEnc, &bstrPlain, &comErr);
            }
        }
        else
        {
            Microsoft::WRL::ComPtr<IOriginalBaseElevator> elevator;

            // Try IElevator2 first if available (Chrome 144+)
            if (iid_v2.has_value())
            {
                hr = CoCreateInstance(clsid, nullptr, CLSCTX_LOCAL_SERVER, iid_v2.value(), &elevator);
            }

            // Fall back to IElevator if v2 not available or failed (Chrome 143 and earlier)
            if (!iid_v2.has_value() || hr == E_NOINTERFACE || FAILED(hr))
            {
                hr = CoCreateInstance(clsid, nullptr, CLSCTX_LOCAL_SERVER, iid, &elevator);
            }

            if (SUCCEEDED(hr))
            {
                CoSetProxyBlanket(elevator.Get(), RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL,
                                  RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_DYNAMIC_CLOAKING);
                hr = elevator->DecryptData(bstrEnc, &bstrPlain, &comErr);
            }
        }

        if (FAILED(hr))
        {
            std::ostringstream oss;
            oss << "DecryptData failed: 0x" << std::hex << hr;
            throw std::runtime_error(oss.str());
        }

        if (!bstrPlain)
            throw std::runtime_error("Decrypted key is null");

        std::unique_ptr<OLECHAR[], BstrDeleter> plainGuard(bstrPlain);
        UINT len = SysStringByteLen(bstrPlain);

        std::vector<uint8_t> result(len);
        memcpy(result.data(), bstrPlain, len);
        return result;
    }

    std::vector<uint8_t> Elevator::DecryptKeyEdgeIID(
        const std::vector<uint8_t> &encryptedKey,
        const CLSID &clsid,
        const IID &iid)
    {
        BSTR bstrEnc = SysAllocStringByteLen(reinterpret_cast<const char *>(encryptedKey.data()), (UINT)encryptedKey.size());
        if (!bstrEnc)
            throw std::runtime_error("SysAllocStringByteLen failed");

        struct BstrDeleter
        {
            void operator()(BSTR b) { SysFreeString(b); }
        };
        std::unique_ptr<OLECHAR[], BstrDeleter> encGuard(bstrEnc);

        BSTR bstrPlain = nullptr;
        DWORD comErr = 0;
        HRESULT hr = E_FAIL;

        // Use Edge interface chain with specified IID
        Microsoft::WRL::ComPtr<IEdgeElevatorFinal> elevator;
        hr = CoCreateInstance(clsid, nullptr, CLSCTX_LOCAL_SERVER, iid, &elevator);

        if (SUCCEEDED(hr))
        {
            CoSetProxyBlanket(elevator.Get(), RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL,
                              RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_DYNAMIC_CLOAKING);
            hr = elevator->DecryptData(bstrEnc, &bstrPlain, &comErr);
        }

        if (FAILED(hr))
        {
            std::ostringstream oss;
            oss << "DecryptData failed: 0x" << std::hex << hr << " (COM err: " << std::dec << comErr << ")";
            throw std::runtime_error(oss.str());
        }

        if (!bstrPlain)
            throw std::runtime_error("Decrypted key is null");

        std::unique_ptr<OLECHAR[], BstrDeleter> plainGuard(bstrPlain);
        UINT len = SysStringByteLen(bstrPlain);

        std::vector<uint8_t> result(len);
        memcpy(result.data(), bstrPlain, len);
        return result;
    }

}
