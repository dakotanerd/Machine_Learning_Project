##############
# Build stage
##############
FROM ubuntu:24.04 as builder

# Install dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    curl \
    wget \
    git \
    cmake \
    g++ \
    python3 \
    python3-pip \
    python3-venv \
    ca-certificates \
    ccache \
    build-essential \
    lsb-release \
    software-properties-common \
    gnupg \
    clang

# Install uv using the installer
ADD https://astral.sh/uv/install.sh /uv-installer.sh
RUN sh /uv-installer.sh && rm /uv-installer.sh
# Add uv to PATH
ENV PATH="/root/.local/bin/:$PATH"

# Install bitnet from source
WORKDIR /
RUN git clone --recursive https://github.com/microsoft/BitNet.git
WORKDIR /BitNet
RUN uv venv && \
    . .venv/bin/activate && \
    uv pip install pip && \
    uv pip install -r requirements.txt --index-strategy unsafe-best-match && \
    mkdir -p models/BitNet-b1.58-2B-4T

# Download the model
ADD https://huggingface.co/microsoft/bitnet-b1.58-2B-4T-gguf/resolve/main/ggml-model-i2_s.gguf models/BitNet-b1.58-2B-4T/ggml-model-i2_s.gguf

# Setup bitnet environment
RUN ./.venv/bin/python setup_env.py -md models/BitNet-b1.58-2B-4T -q i2_s

########################
# Final stage
########################
FROM ubuntu:24.04
# Install Python in final stage
RUN apt-get update && \
    apt-get install -y python3 && \
    rm -rf /var/lib/apt/lists/*

RUN useradd modeluser

COPY --from=builder --chown=modeluser:modeluser /BitNet/ /home/modeluser/BitNet/
COPY --from=builder /BitNet/build/3rdparty/llama.cpp/src/libllama.so /usr/lib/
COPY --from=builder /BitNet/build/3rdparty/llama.cpp/ggml/src/libggml.so /usr/lib/
COPY chat.sh /home/modeluser/BitNet/chat.sh
COPY chat.py /home/modeluser/BitNet/chat.py

WORKDIR /home/modeluser/BitNet

RUN chmod +x /home/modeluser/BitNet/chat.sh && \
    chmod +x /home/modeluser/BitNet/chat.py && \
    rm -f /usr/local/bin/chat && \
    ln -s /home/modeluser/BitNet/chat.py /usr/local/bin/chat

USER modeluser

CMD ["/bin/bash"]
