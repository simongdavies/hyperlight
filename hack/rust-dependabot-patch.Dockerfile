FROM dependabot/dependabot-script
RUN rustup toolchain install 1.84.0 && rustup default 1.84.0
