FROM debian:trixie AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential cmake ninja-build ca-certificates git \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY CMakeLists.txt ./
COPY cmake cmake
COPY src src
COPY tests tests
RUN cmake -S . -B /build -G Ninja -DCMAKE_BUILD_TYPE=Release \
      -DBOT_SHIELD_BUILD_TESTS=OFF \
 && cmake --build /build --target bot-shield \
 && strip /build/src/bot-shield

FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/src/bot-shield /usr/local/bin/bot-shield
COPY deploy/bot-shield.yaml /etc/bot-shield/bot-shield.yaml
ENTRYPOINT ["/usr/local/bin/bot-shield", "--config", "/etc/bot-shield/bot-shield.yaml"]
