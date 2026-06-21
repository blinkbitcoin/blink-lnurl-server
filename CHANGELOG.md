# [blink-lnurl-server release v0.5.0](https://github.com/blinkbitcoin/blink-lnurl-server/releases/tag/0.5.0)


### Features

- Add internal Blink default wallet update API (#27)

# [blink-lnurl-server release v0.4.1](https://github.com/blinkbitcoin/blink-lnurl-server/releases/tag/0.4.1)


### Refactor

- Namespace internal Blink scopes (#26)

# [blink-lnurl-server release v0.4.0](https://github.com/blinkbitcoin/blink-lnurl-server/releases/tag/0.4.0)


### Features

- Add config toggles for Spark and Blink providers (#22)

### Refactor

- Replace legacy users schema with account-backed spark compatibility (#25)

# [blink-lnurl-server release v0.3.1](https://github.com/blinkbitcoin/blink-lnurl-server/releases/tag/0.3.1)


### Bug Fixes

- Return LNURL errors for missing public identifiers (#21)

# [blink-lnurl-server release v0.3.0](https://github.com/blinkbitcoin/blink-lnurl-server/releases/tag/0.3.0)


### Bug Fixes

- Default deployment env to production
- Validate blink endpoint config

### Documentation

- Update deployment env default
- Document DEPLOYMENT_ENV runtime mapping
- Update project documentation (#16)

### Features

- Add provider runtime overrides
- Derive provider runtime from DEPLOYMENT_ENV

### Refactor

- Make runtime config explicit
- Simplify deployment runtime config
- Remove network alias
- Name deployment env constants
- Cut provider and webhook indirection (#19)

### Styling

- Apply rustfmt cleanup

### Testing

- Remove source content assertions
- Update runtime config boundary assertion
- Harden e2e startup

# [blink-lnurl-server release v0.2.0](https://github.com/blinkbitcoin/blink-lnurl-server/releases/tag/0.2.0)


### Features

- Add Blink provider support (#15)

# [blink-lnurl-server release v0.1.0](https://github.com/blinkbitcoin/blink-lnurl-server/releases/tag/0.1.0)


### Documentation

- Update README and Dockerfiles (#9)

### Features

- Bootstrap lnurl server (#1)

### Miscellaneous Tasks

- Clean unused dependencies (#10)
- Bump lightning-invoice from 0.33.2 to 0.34.0 (#6)
- Bump DeterminateSystems/magic-nix-cache-action (#3)
- Bump DeterminateSystems/nix-installer-action from 21 to 22 (#2)
- Initialize repository
