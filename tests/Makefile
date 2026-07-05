# mbedtls 3.x is required (4.x removed the legacy mbedtls_aes/gcm API the
# ESP32 Arduino core also uses): brew install mbedtls@3
MBEDTLS_PREFIX ?= $(shell brew --prefix mbedtls@3 2>/dev/null || echo /usr/local)
CXX ?= c++
CXXFLAGS = -std=gnu++17 -g -Wall -Wextra -I stubs -I ../../src -I $(MBEDTLS_PREFIX)/include
LDFLAGS = -L $(MBEDTLS_PREFIX)/lib -lmbedcrypto

build/lynktuya_tests: lynktuya_tests.cpp stubs/Arduino.h stubs/WiFi.h ../src/LynkTuya.h
	mkdir -p build
	$(CXX) $(CXXFLAGS) lynktuya_tests.cpp -o $@ $(LDFLAGS)

test: build/lynktuya_tests
	./build/lynktuya_tests

clean:
	rm -rf build

.PHONY: test clean
