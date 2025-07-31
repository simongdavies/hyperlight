FROM dependabot/dependabot-script
RUN rustup toolchain install 1.86 && rustup default 1.86
