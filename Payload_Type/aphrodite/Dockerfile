FROM itsafeaturemythic/mythic_python_base:latest

RUN apt-get update && apt-get install -y \
    curl xz-utils mingw-w64 gcc git libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install donut-shellcode

ENV NIM_VERSION=2.0.4
RUN curl -L https://nim-lang.org/download/nim-${NIM_VERSION}-linux_x64.tar.xz -o /tmp/nim.tar.xz \
    && tar -xf /tmp/nim.tar.xz -C /opt \
    && mv /opt/nim-${NIM_VERSION} /opt/nim \
    && rm /tmp/nim.tar.xz

ENV PATH="/opt/nim/bin:/root/.nimble/bin:${PATH}"

# Install nimcrypto directly into Nim's stdlib path (no nimble registry needed)
RUN git clone --depth 1 https://github.com/cheatfate/nimcrypto.git /tmp/nimcrypto \
    && cp -r /tmp/nimcrypto/nimcrypto /opt/nim/lib/nimcrypto \
    && echo "include rijndael" > /opt/nim/lib/nimcrypto/aes.nim \
    && rm -rf /tmp/nimcrypto

WORKDIR /Mythic/
CMD ["python3", "main.py"]
