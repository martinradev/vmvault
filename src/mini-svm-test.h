#ifndef MINI_SVM_TEST_H
#define MINI_SVM_TEST_H

#if 0
static void runSetKeyTests(MiniSvmCommunicationBlock &commBlock) {
        // Send valid keys.
        uint16_t contextIdCounter {};
        for (auto keylen : {16, 24, 32}) {
                uint8_t key[keylen] {};
                uint16_t contextId;
                const auto result { registerContext(commBlock, &key[0], keylen, NULL, 0, &contextId) };
                assert(result == MiniSvmReturnResult::Ok);
                assert(contextIdCounter == contextId);
                ++contextIdCounter;
        }

        // Destroy the keys.
        auto result { removeContext(commBlock, 0) };
        assert(result == MiniSvmReturnResult::Ok);
        result = removeContext(commBlock, 1);
        assert(result == MiniSvmReturnResult::Ok);
        result = removeContext(commBlock, 2);
        assert(result == MiniSvmReturnResult::Ok);

        // Send an invalid key
        {
                const uint8_t key[100] {};
                uint16_t contextId;
                result = registerContext(commBlock, &key[0], sizeof(key), NULL, 0, &contextId);
                assert(result != MiniSvmReturnResult::Ok);
                result = registerContext(commBlock, &key[0], std::numeric_limits<uint16_t>::max(), NULL, 0, &contextId);
                assert(result != MiniSvmReturnResult::Ok);
                result = registerContext(commBlock, &key[0], 0, NULL, 0, &contextId);
                assert(result != MiniSvmReturnResult::Ok);
        }

        // Check iv
        {
                const uint8_t key[16] {};
                uint16_t contextId;
                const uint8_t iv[32] {};

                result = registerContext(commBlock, &key[0], sizeof(key), iv, sizeof(iv), &contextId);
                assert(result != MiniSvmReturnResult::Ok);

                result = registerContext(commBlock, &key[0], sizeof(key), iv, sizeof(key), &contextId);
                assert(result == MiniSvmReturnResult::Ok);
                result = removeContext(commBlock, contextId);
                assert(result == MiniSvmReturnResult::Ok);

                result = registerContext(commBlock, &key[0], sizeof(key), iv, 4U, &contextId);
                assert(result != MiniSvmReturnResult::Ok);
        }

        // Try to delete unexisting keys.
        result = removeContext(commBlock, 1337);
        assert(result != MiniSvmReturnResult::Ok);
        result = removeContext(commBlock, 13);
        assert(result != MiniSvmReturnResult::Ok);

        // Try to fill up keys.
        uint8_t key[16] {};
       uint8_t key[16] {};
        uint16_t contextId;
        for (size_t i {}; true; ++i) {
                result = registerContext(commBlock, &key[0], sizeof(key), NULL, 0, &contextId);
                if (result != MiniSvmReturnResult::Ok) {
                        break;
                }
        }
        result = registerContext(commBlock, &key[0], sizeof(key), NULL, 0, &contextId);
        assert(result != MiniSvmReturnResult::Ok);

        for (size_t i {}; true; ++i) {
                result = removeContext(commBlock, i);
                if (result != MiniSvmReturnResult::Ok) {
                        break;
                }
        }
}

static void runEncDecTests(MiniSvmCommunicationBlock &commBlock) {
        /* EBC tests */
        // Small block
        {
                std::array<uint8_t, 16> key {};
                key.fill(0x41U);
                uint16_t keyId;
                auto result { registerContext(commBlock, key, NULL, 0, &keyId) };
                assert(result == MiniSvmReturnResult::Ok);
                assert(keyId >= 0);

                std::array<uint8_t, 16> data {};
                data.fill(0x42U);
                std::array<uint8_t, 16> output {};
                result = encryptData(commBlock, keyId, MiniSvmCipher::AesEcb, data.data(), data.size(), output.data());
                assert(result == MiniSvmReturnResult::Ok);
                constexpr std::array<uint8_t, 16> expected
                        { 0x31U, 0xe3U, 0x3aU, 0x6eU, 0x52U, 0x50U, 0x90U, 0x9aU, 0x7eU, 0x51U, 0x8cU, 0xe7U, 0x6dU, 0x2cU, 0x9fU, 0x79U };
                assert(memcmp(output.data(), expected.data(), data.size()) == 0);

                std::array<uint8_t, 16> keyDec {};
                keyDec.fill(0x41U);
                uint16_t keyDecId;
                result = registerContext(commBlock, keyDec, NULL, 0, &keyDecId);
                assert(result == MiniSvmReturnResult::Ok);
                assert(keyDecId >= 0);

                std::array<uint8_t, 16> revert {};
                result = decryptData(commBlock, keyDecId, MiniSvmCipher::AesEcb, expected.data(), expected.size(), revert.data());
                assert(result == MiniSvmReturnResult::Ok);
                assert(memcmp(revert.data(), data.data(), data.size()) == 0);
        }

        // Multiple blocks
        {
                std::array<uint8_t, 16> key;
                std::iota(key.begin(), key.end(), 0);
                std::array<uint8_t, 96> input;
                std::iota(input.begin(), input.end(), 32);
                std::array<uint8_t, 96> output;
                constexpr std::array<uint8_t, 96> expected { 0x5bU, 0xe8U, 0x7eU, 0x2eU, 0x5bU, 0x44U, 0x7cU, 0x94U, 0x4bU, 0x21U, 0xc9U, 0xafU, 0x77U, 0x56U, 0xc0U, 0xd8U, 0x3U, 0xf2U, 0xc3U, 0xbdU, 0xcaU, 0x82U, 0x6bU, 0xf0U, 0x82U, 0xd7U, 0xcfU, 0xb0U, 0x35U, 0xcdU, 0xb8U, 0xc1U, 0xd5U, 0x33U, 0xe5U, 0x9bU, 0x45U, 0xa1U, 0x53U, 0xedU, 0x7eU, 0x5eU, 0x9cU, 0x5dU, 0xfcU, 0xfdU, 0x4aU, 0xaaU, 0x3eU, 0xf0U, 0xb1U, 0xa5U, 0xe3U, 0x5U, 0x9dU, 0xabU, 0x21U, 0xfcU, 0xe2U, 0x3aU, 0x7bU, 0x61U, 0xc4U, 0xcaU, 0xadU, 0xdeU, 0x68U, 0xf7U, 0xadU, 0x49U, 0x72U, 0x68U, 0xd3U, 0x1aU, 0xdU, 0xddU, 0x5cU, 0x74U, 0xb0U, 0x8fU, 0x3dU, 0x2dU, 0x90U, 0xdcU, 0xefU, 0x49U, 0xd3U, 0x28U, 0x22U, 0x29U, 0x8bU, 0x87U, 0x8fU, 0x81U, 0x55U, 0x81U };

                uint16_t keyId;
                auto result { registerContext(commBlock, key, NULL, 0, &keyId) };
                assert(result == MiniSvmReturnResult::Ok);
                assert(keyId >= 0);
                result = encryptData(commBlock, keyId, MiniSvmCipher::AesEcb, input.data(), input.size(), output.data());
                assert(memcmp(output.data(), expected.data(), output.size()) == 0);

                result = registerContext(commBlock, key, NULL, 0, &keyId);
                assert(result == MiniSvmReturnResult::Ok);
                assert(keyId >= 0);
                std::array<uint8_t, 96> revert;
                result = decryptData(commBlock, keyId, MiniSvmCipher::AesEcb, expected.data(), expected.size(), revert.data());
                assert(memcmp(input.data(), revert.data(), revert.size()) == 0);
        }

        // Invalid block size
        {
                std::array<uint8_t, 16> key;
                std::iota(key.begin(), key.end(), 0);
                std::array<uint8_t, 44> input;
                std::array<uint8_t, 44> output;

                uint16_t keyId;
                auto result { registerContext(commBlock, key, NULL, 0, &keyId) };
                assert(result == MiniSvmReturnResult::Ok);
                assert(keyId >= 0);
                result = encryptData(commBlock, keyId, MiniSvmCipher::AesEcb, input.data(), input.size(), output.data());
                assert(result != MiniSvmReturnResult::Ok);

                result = decryptData(commBlock, keyId, MiniSvmCipher::AesEcb, input.data(), input.size(), output.data());
                assert(result != MiniSvmReturnResult::Ok);
        }

        /* CBC tests */
        // Single block
        {
                std::array<uint8_t, 16> output;
                output.fill(0x0);
                std::array<uint8_t, 16> key {};
                key.fill(0x41U);
                std::array<uint8_t, 16> iv {};
                iv.fill(0x42U);
                std::array<uint8_t, 16> input {};
                input.fill(0x43U);
                uint16_t keyId;
                auto result { registerContext(commBlock, key, iv.data(), iv.size(), &keyId) };
                assert(result == MiniSvmReturnResult::Ok);
                assert(keyId >= 0);
                constexpr std::array<uint8_t, 16> expected { 0xaaU, 0x1aU, 0x18U, 0xffU, 0x55U, 0x61U, 0x5fU, 0x61U, 0x22U, 0xf2U, 0x87U, 0x48U, 0x65U, 0xc8U, 0x1bU, 0xfcU };
                result = encryptData(commBlock, keyId, MiniSvmCipher::AesCbc, input.data(), input.size(), output.data());
                assert(result == MiniSvmReturnResult::Ok);
                assert(memcmp(output.data(), expected.data(), output.size()) == 0);

                std::array<uint8_t, 16> revert;
                result = registerContext(commBlock, key, iv.data(), iv.size(), &keyId);
                assert(result == MiniSvmReturnResult::Ok);
                result = decryptData(commBlock, keyId, MiniSvmCipher::AesCbc, output.data(), output.size(), revert.data());
                assert(result == MiniSvmReturnResult::Ok);
                assert(memcmp(revert.data(), input.data(), input.size()) == 0);
        }

        // Multiple blocks
        {
                std::array<uint8_t, 96> output;
                output.fill(0x0);
                std::array<uint8_t, 16> key {};
                key.fill(0x41U);
                std::array<uint8_t, 16> iv {};
                iv.fill(0x42U);
                std::array<uint8_t, 96> input {};
                input.fill(0x43U);
                uint16_t keyId;
                auto result { registerContext(commBlock, key, iv.data(), iv.size(), &keyId) };
                assert(result == MiniSvmReturnResult::Ok);
                assert(keyId >= 0);
                constexpr std::array<uint8_t, 96> expected
                { 0xaaU, 0x1aU, 0x18U, 0xffU, 0x55U, 0x61U, 0x5fU, 0x61U, 0x22U, 0xf2U, 0x87U, 0x48U, 0x65U, 0xc8U, 0x1bU, 0xfcU, 0xf9U, 0xcbU, 0x40U, 0xedU, 0xf6U, 0x4eU, 0xd0U, 0x2dU, 0x9dU, 0x31U, 0x72U, 0x42U, 0xd1U, 0xf2U, 0x5aU, 0x0U, 0x9bU, 0x94U, 0xd5U, 0x38U, 0xeeU, 0x37U, 0x46U, 0x51U, 0xf3U, 0x69U, 0x53U, 0x98U, 0x10U, 0xeeU, 0xe4U, 0xa9U, 0x5bU, 0xc8U, 0xa3U, 0xfdU, 0x98U, 0xdbU, 0x29U, 0x15U, 0x55U, 0xd3U, 0xa8U, 0x7aU, 0x4bU, 0xadU, 0x5U, 0x49U, 0x22U, 0xdU, 0x84U, 0x7U, 0x7cU, 0x59U, 0xeeU, 0xeaU, 0x20U, 0x2U, 0xdeU, 0x79U, 0x6bU, 0x34U, 0xaaU, 0x7dU, 0xeU, 0xafU, 0x57U, 0x3eU, 0x9bU, 0x11U, 0x98U, 0xb1U, 0xf8U, 0xb7U, 0x84U, 0x81U, 0x16U, 0xefU, 0xbcU, 0x32U };
                result = encryptData(commBlock, keyId, MiniSvmCipher::AesCbc, input.data(), input.size(), output.data());
                assert(result == MiniSvmReturnResult::Ok);
                assert(memcmp(output.data(), expected.data(), output.size()) == 0);

                result = registerContext(commBlock, key, iv.data(), iv.size(), &keyId);
                assert(result == MiniSvmReturnResult::Ok);
                assert(keyId >= 0);
                std::array<uint8_t, 96> revert {};
                result = decryptData(commBlock, keyId, MiniSvmCipher::AesCbc, output.data(), output.size(), revert.data());
                assert(result == MiniSvmReturnResult::Ok);
                assert(memcmp(revert.data(), input.data(), revert.size()) == 0);
        }
}
#endif

#endif
