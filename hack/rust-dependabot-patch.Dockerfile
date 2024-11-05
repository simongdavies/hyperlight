FROM dependabot/dependabot-script
RUN rustup toolchain install 1.81.0 && rustup default 1.81.0
